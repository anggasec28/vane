"""Authorization-gated observation contracts and passive HTTP metadata adapter."""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Protocol
from urllib.parse import urlsplit
from uuid import uuid4

from vane.models import AuthorizationEnvelope, EvidenceRecord
from vane.security.approval import Approval
from vane.security.enforcement import SecurityEnforcer


@dataclass(frozen=True, slots=True)
class ObservationRequest:
    locator: str
    method: str
    purpose: str
    authorization: AuthorizationEnvelope
    mission_id: str = ""
    mission_approval: Approval | None = None
    action_approval: Approval | None = None


@dataclass(frozen=True, slots=True)
class ObservationResult:
    success: bool
    summary: str
    evidence: EvidenceRecord | None = None
    blocked_reason: str | None = None


class ObservationAdapter(Protocol):
    def observe(self, request: ObservationRequest) -> ObservationResult: ...


MetadataTransport = Callable[
    [str, int, str, dict[str, str], float],
    tuple[int, dict[str, str], str],
]


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._address, self.port), self.timeout, self.source_address
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        self._ssl_context = ssl.create_default_context()
        super().__init__(host, port, timeout=timeout, context=self._ssl_context)
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._address, self.port), self.timeout, self.source_address
        )
        self.sock = self._ssl_context.wrap_socket(raw, server_hostname=self.host)


def _public_addresses(host: str, port: int) -> tuple[str, ...]:
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"DNS resolution failed: {exc}") from exc
    addresses = tuple(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise ValueError("Hostname resolved to no addresses.")
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("DNS returned an invalid IP address.") from exc
        if not parsed.is_global:
            raise ValueError("HTTP metadata adapter refuses non-public destination addresses.")
    return addresses


def _pinned_head(
    locator: str, timeout: float, user_agent: str
) -> tuple[int, dict[str, str], str]:
    parsed = urlsplit(locator)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only absolute HTTP and HTTPS URLs are supported.")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("URL credentials and fragments are not accepted.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = _public_addresses(parsed.hostname, port)
    address = addresses[0]
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    host_header = parsed.hostname
    if parsed.port:
        host_header += f":{parsed.port}"
    headers = {
        "Host": host_header,
        "User-Agent": user_agent,
        "Accept": "*/*",
        "Connection": "close",
    }
    connection_type = _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
    connection = connection_type(parsed.hostname, port, address, timeout)
    try:
        connection.request("HEAD", path, headers=headers)
        response = connection.getresponse()
        safe_names = {
            "cache-control", "content-length", "content-security-policy", "content-type",
            "date", "etag", "last-modified", "permissions-policy", "referrer-policy",
            "server", "strict-transport-security", "x-content-type-options", "x-frame-options",
        }
        safe_headers = {
            key.lower(): value[:2048]
            for key, value in response.getheaders()
            if key.lower() in safe_names
        }
        protocol = {9: "HTTP/0.9", 10: "HTTP/1.0", 11: "HTTP/1.1"}.get(
            response.version, f"HTTP/version-{response.version}"
        )
        return response.status, safe_headers, protocol
    finally:
        connection.close()


class HTTPMetadataAdapter:
    """Collect response headers only after central authorization and signed mission approval.

    Redirects are not followed, response bodies are never read, DNS results must be public,
    and the TCP/TLS connection is pinned to the validated IP address.
    """

    def __init__(
        self,
        enforcer: SecurityEnforcer,
        *,
        timeout: float = 8.0,
        user_agent: str = "VANE-Authorized-Metadata/1.0",
        transport: MetadataTransport | None = None,
    ) -> None:
        if not 0.1 <= timeout <= 30:
            raise ValueError("timeout must be between 0.1 and 30 seconds.")
        if not user_agent.strip():
            raise ValueError("user_agent must not be empty.")
        self._enforcer = enforcer
        self._timeout = timeout
        self._user_agent = user_agent
        self._transport = transport or self._default_transport

    def _default_transport(
        self, locator: str, port: int, path: str, headers: dict[str, str], timeout: float
    ) -> tuple[int, dict[str, str], str]:
        del port, path, headers, timeout
        return _pinned_head(locator, self._timeout, self._user_agent)

    def observe(self, request: ObservationRequest) -> ObservationResult:
        if request.method.casefold() != "http_metadata":
            return ObservationResult(False, "Observation blocked.", blocked_reason="Unsupported method.")
        if not request.mission_id.strip() or request.mission_approval is None:
            return ObservationResult(
                False, "Observation blocked.",
                blocked_reason="Mission ID and signed mission approval are required.",
            )
        decision = self._enforcer.authorize_action(
            request.authorization, request.locator, request.method,
            mission_approval=request.mission_approval,
            action_approval=request.action_approval,
        )
        if not decision.allowed:
            return ObservationResult(False, "Observation blocked.", blocked_reason=decision.reason)
        try:
            parsed = urlsplit(request.locator)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("Only absolute HTTP and HTTPS URLs are supported.")
            if parsed.username or parsed.password or parsed.fragment:
                raise ValueError("URL credentials and fragments are not accepted.")
            status, headers, protocol = self._transport(
                request.locator, parsed.port or (443 if parsed.scheme == "https" else 80),
                parsed.path or "/", {
                    "Host": parsed.hostname,
                    "User-Agent": self._user_agent,
                    "Accept": "*/*",
                    "Connection": "close",
                }, self._timeout,
            )
            canonical = json.dumps(
                {"status": status, "headers": headers, "protocol": protocol},
                sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            )
            evidence = EvidenceRecord(
                evidence_id=str(uuid4()),
                project_id=request.authorization.project_id,
                mission_id=request.mission_id,
                kind="http_metadata",
                source=request.locator,
                observed_at=datetime.now(timezone.utc),
                content_digest=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                authorization_id=request.authorization.envelope_id,
                collection_method="http_head",
                limitations=[
                    "HEAD response only; response body was not collected.",
                    "Redirects are recorded but never followed.",
                    "Metadata is an observation, not proof of vulnerability.",
                ],
                metadata={
                    "status_code": status, "headers": headers, "protocol": protocol,
                    "locator": request.locator, "method": request.method,
                },
            )
            return ObservationResult(True, f"HTTP {status} metadata collected.", evidence=evidence)
        except Exception as exc:
            return ObservationResult(False, "HTTP metadata collection failed.", blocked_reason=str(exc))


def build_assessment_plan(authorization: AuthorizationEnvelope, assets: list, platform: str = "web2") -> dict:
    """Build an eleven-phase plan; never performs network or target actions."""
    from vane.errors import AuthorizationError
    from vane.models import AssetDisposition
    from vane.security.authorization import asset_is_in_scope

    if not authorization.is_time_valid():
        raise AuthorizationError("A current, approved authorization envelope is required.")
    platform_key = platform.strip().casefold()
    if platform_key not in {"web2", "web3", "hybrid"}:
        raise ValueError("platform must be web2, web3, or hybrid")
    in_scope = []
    for asset in assets:
        if asset.disposition != AssetDisposition.IN_SCOPE:
            continue
        if not asset_is_in_scope(asset.locator, authorization.rules):
            raise AuthorizationError(f"Asset marked IN_SCOPE is outside authorization: {asset.locator}")
        in_scope.append(asset.asset_id)
    if not in_scope:
        raise AuthorizationError("At least one explicitly IN_SCOPE asset is required.")
    asset_ids = sorted(set(in_scope))
    methods = sorted({method.casefold() for method in authorization.allowed_methods})
    phases = []
    previous = []
    phase_specs = (
        ("MISSION_COMPREHENSION", "Confirm objective, ownership, exact scope and stop conditions.", "MASTER_SCOPE_REVIEW"),
        ("STRATEGIC_INTELLIGENCE", "Review permitted context and source confidence.", "AUTHORIZED_SOURCES_ONLY"),
        ("ECOSYSTEM_DISCOVERY", "Inventory explicitly authorized assets; discoveries never inherit scope.", "SCOPE_CHECK_PER_ASSET"),
        ("ADVERSARIAL_MODELING", "Map trust boundaries and evidence-backed attack-surface hypotheses.", "EVIDENCE_REQUIRED"),
        ("ADAPTIVE_PLANNING", "Prioritize evidence objectives, dependencies and permitted methods.", "METHOD_ALLOWLIST"),
        ("SPECIALIST_ORCHESTRATION", "Prepare finite specialist tasks with asset and method allowlists.", "WORKER_CONTRACT_REQUIRED"),
        ("DEEP_INVESTIGATION", "Use reviewed adapters with per-action authorization and provenance.", "ACTION_AUTHORIZATION"),
        ("EXPLOITABILITY_IMPACT", "Assess impact only within separately approved methods.", "HIGH_RISK_APPROVAL"),
        ("EVIDENCE_VALIDATION", "Correlate evidence and independently challenge claims.", "INDEPENDENT_VALIDATION"),
        ("STRATEGIC_REASSESSMENT", "Reprioritize without expanding the authorization envelope.", "REAUTHORIZE_SCOPE_CHANGE"),
        ("REPORTING_KNOWLEDGE", "Produce evidence-linked findings, limitations and closure recommendation.", "SIGNED_CLOSURE"),
    )
    for index, (name, objective, gate) in enumerate(phase_specs, 1):
        uses_assets = name in {
            "ECOSYSTEM_DISCOVERY", "SPECIALIST_ORCHESTRATION",
            "DEEP_INVESTIGATION", "EXPLOITABILITY_IMPACT",
        }
        mode = "PLANNING_ONLY"
        if name == "SPECIALIST_ORCHESTRATION":
            mode = "BOUNDED_DELEGATION_CONTRACT_ONLY"
        elif name == "DEEP_INVESTIGATION":
            mode = "REQUIRES_REVIEWED_ADAPTER_AND_PER_ACTION_AUTHORIZATION"
        elif name == "EXPLOITABILITY_IMPACT":
            mode = "SEPARATE_HIGH_RISK_APPROVAL_REQUIRED"
        phase_id = f"P{index:02d}"
        phases.append({
            "phase_id": phase_id, "name": name,
            "objective": f"{platform_key.upper()}: {objective}",
            "depends_on": previous,
            "execution_mode": mode,
            "asset_ids": asset_ids if uses_assets else [],
            "required_methods": methods if name == "DEEP_INVESTIGATION" else [],
            "gate": gate, "status": "PLANNED",
        })
        previous = [phase_id]
    return {
        "plan_type": "VANE_ADAPTIVE_ASSESSMENT_WORKFLOW",
        "platform": platform_key,
        "authorization_id": authorization.envelope_id,
        "execution_performed": False,
        "target_requests_performed": False,
        "phases": phases,
    }


def _flatten_certificate_name(name: tuple) -> list[str]:
    return [f"{key}={value}" for relative_name in name for key, value in relative_name]


def _pinned_certificate(locator: str, timeout: float) -> dict[str, object]:
    parsed = urlsplit(locator)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("TLS certificate observation requires an absolute HTTPS URL.")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("URL credentials and fragments are not accepted.")
    port = parsed.port or 443
    addresses = _public_addresses(parsed.hostname, port)
    connection = _PinnedHTTPSConnection(parsed.hostname, port, addresses[0], timeout)
    try:
        connection.connect()
        if connection.sock is None:
            raise OSError("TLS socket was not established.")
        certificate = connection.sock.getpeercert()
        encoded = connection.sock.getpeercert(binary_form=True)
        if not certificate or not encoded:
            raise ValueError("Peer did not provide a verifiable TLS certificate.")
        sans = [
            f"{kind}:{value}" for kind, value in certificate.get("subjectAltName", [])
            if kind in {"DNS", "IP Address"}
        ][:256]
        return {
            "subject": _flatten_certificate_name(certificate.get("subject", ())),
            "issuer": _flatten_certificate_name(certificate.get("issuer", ())),
            "serial_number": certificate.get("serialNumber"),
            "not_before": certificate.get("notBefore"),
            "not_after": certificate.get("notAfter"),
            "subject_alt_names": sans,
            "version": certificate.get("version"),
            "sha256_fingerprint": hashlib.sha256(encoded).hexdigest(),
        }
    finally:
        connection.close()


class TLSMetadataAdapter:
    """Collect verified TLS certificate metadata from one explicitly authorized HTTPS asset."""

    def __init__(
        self,
        enforcer: SecurityEnforcer,
        *,
        timeout: float = 8.0,
        transport: Callable[[str, float], dict[str, object]] | None = None,
    ) -> None:
        if not 0.1 <= timeout <= 30:
            raise ValueError("timeout must be between 0.1 and 30 seconds.")
        self._enforcer = enforcer
        self._timeout = timeout
        self._transport = transport or _pinned_certificate

    def observe(self, request: ObservationRequest) -> ObservationResult:
        if request.method.casefold() != "tls_metadata":
            return ObservationResult(False, "Observation blocked.", blocked_reason="Unsupported method.")
        if not request.mission_id.strip() or request.mission_approval is None:
            return ObservationResult(
                False, "Observation blocked.",
                blocked_reason="Mission ID and signed mission approval are required.",
            )
        decision = self._enforcer.authorize_action(
            request.authorization, request.locator, request.method,
            mission_approval=request.mission_approval,
            action_approval=request.action_approval,
        )
        if not decision.allowed:
            return ObservationResult(False, "Observation blocked.", blocked_reason=decision.reason)
        try:
            metadata = self._transport(request.locator, self._timeout)
            canonical = json.dumps(
                metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            )
            evidence = EvidenceRecord(
                evidence_id=str(uuid4()),
                project_id=request.authorization.project_id,
                mission_id=request.mission_id,
                kind="tls_certificate",
                source=request.locator,
                observed_at=datetime.now(timezone.utc),
                content_digest=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                authorization_id=request.authorization.envelope_id,
                collection_method="tls_handshake",
                limitations=[
                    "TLS handshake and peer certificate metadata only.",
                    "No HTTP request or application-layer content was collected.",
                    "Certificate metadata is an observation, not proof of a vulnerability.",
                ],
                metadata={
                    **metadata, "locator": request.locator, "method": request.method,
                },
            )
            return ObservationResult(
                True, "TLS certificate metadata collected.", evidence=evidence
            )
        except Exception as exc:
            return ObservationResult(
                False, "TLS certificate collection failed.", blocked_reason=str(exc)
            )

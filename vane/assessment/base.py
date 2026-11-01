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

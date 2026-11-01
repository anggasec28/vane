"""Public application facade for embedding VANE in a host runtime."""
from vane.core.orchestrator import AssessmentOrchestrator
from copy import deepcopy
from datetime import datetime
from vane.assessment.asset_mapping import classify_discovered_asset
from vane.core.state_machine import transition
from vane.errors import PolicyViolation
from vane.evidence.manager import validate_evidence
from vane.findings.governance import validate_finding
from vane.findings.reporting import ReportBundle, build_report
from vane.findings.remediation import RemediationAction, validate_remediation, validate_remediation_graph
from vane.intelligence.threat_intel import ThreatIntelRecord
from vane.projects.case_ops import CaseTimelineEvent, CaseWorkItem
from vane.models import (
    Asset, AuthorizationEnvelope, EvidenceRecord, Finding, FindingStatus, Mission, MissionStatus, utc_now,
)
from vane.projects.registry import Project, ProjectRegistry
from vane.security.approval import Approval
from vane.security.digests import (authorization_digest, capability_action_digest, mission_closure_digest)
from vane.security.enforcement import SecurityEnforcer
from vane.security.authorization import asset_is_in_scope
from vane.security.policy_engine import HIGH_RISK_METHODS
from vane.storage.repository import SQLiteRepository
from vane.storage.governance_repository import GovernanceRepository
from vane.validation.independent import validate_mission_closure
from vane.workers.contracts import WorkerTask
from vane.workers.orchestrator import WorkerAssignment, WorkerOrchestrator
from vane.workers.catalog import default_specialist_registry


class VaneEngine:
    """Composition root. Persistence and trusted approval verification are injected."""

    def __init__(self, *, enforcer: SecurityEnforcer | None = None,
                 projects: ProjectRegistry | None = None,
                 repository: SQLiteRepository | None = None) -> None:
        self.enforcer = enforcer or SecurityEnforcer()
        self.projects = projects or ProjectRegistry()
        self.repository = repository
        self.governance_repository = GovernanceRepository(repository.store) if repository is not None else None
        self.orchestrator = AssessmentOrchestrator(self.enforcer)
        self.specialists = default_specialist_registry()
        self.workers = WorkerOrchestrator(self.specialists)
        self._worker_project_ids: dict[str, str] = {}
        self._authorization_cache: dict[str, AuthorizationEnvelope] = {}
        self._approval_cache: dict[str, Approval] = {}

    def _trusted_authorization(self, project_id: str, envelope_id: str,
                                now: datetime | None = None) -> tuple[AuthorizationEnvelope, Approval]:
        current = now or utc_now()
        if self.repository is not None:
            envelope = self.repository.get_authorization(project_id, envelope_id)
            approval = self.repository.get_approval(project_id, envelope.approval_id)
        else:
            envelope = self._authorization_cache.get(envelope_id)
            approval = self._approval_cache.get(envelope.approval_id) if envelope else None
        if (envelope is None or approval is None or envelope.project_id != project_id
                or not envelope.is_time_valid(current)
                or not self.enforcer.validate_approval(approval, authorization_digest(envelope),
                    envelope.approval_id, now=current)
                or approval.expires_at is None or approval.expires_at > envelope.expires_at):
            raise PolicyViolation("A valid signed authorization envelope is required.")
        return envelope, approval

    def register_project(self, project_id: str, name: str, owner: str) -> Project:
        if not all(value.strip() for value in (project_id, name, owner)):
            raise ValueError("project_id, name, and owner are required.")
        try:
            self.projects.get(project_id)
        except KeyError:
            pass
        else:
            raise ValueError(f"Project already exists: {project_id}")
        if self.repository is not None:
            try:
                self.repository.get_project(project_id)
            except KeyError:
                pass
            else:
                raise ValueError(f"Project already exists: {project_id}")
        project = Project(project_id, name, owner)
        if self.repository is not None:
            self.repository.save_project(project)
        self.projects.add(project)
        return project

    def get_project(self, project_id: str) -> Project:
        try:
            return self.projects.get(project_id)
        except KeyError:
            if self.repository is None:
                raise
            project = self.repository.get_project(project_id)
            self.projects.add(project)
            return project

    def create_mission(self, project_id: str, objective: str,
                       required_evidence: set[str] | None = None) -> Mission:
        if not objective.strip():
            raise ValueError("Mission objective must not be empty.")
        project = self.get_project(project_id)
        mission = Mission.create(project_id, objective)
        mission.required_evidence = set(required_evidence or set())
        if self.repository is not None:
            self.repository.save_mission(mission)
        project.missions[mission.mission_id] = mission
        return mission

    def get_mission(self, project_id: str, mission_id: str) -> Mission:
        project = self.get_project(project_id)
        if mission_id in project.missions:
            return project.missions[mission_id]
        if self.repository is None:
            raise KeyError(mission_id)
        mission = self.repository.get_mission(project_id, mission_id)
        project.missions[mission_id] = mission
        return mission

    def submit_mission(self, mission: Mission, *, actor: str = "master") -> Mission:
        previous_history = list(mission.history)
        result = self.orchestrator.submit_for_approval(mission, actor=actor)
        if self.repository is not None:
            try:
                self.repository.save_mission(result, actor=actor)
            except Exception:
                mission.status = MissionStatus.DRAFT
                mission.history = previous_history
                raise
        return result

    def authorize_mission(self, mission: Mission, envelope: AuthorizationEnvelope,
                          approval: Approval, *, actor: str = "master") -> Mission:
        previous_status = mission.status
        previous_authorization_id = mission.authorization_id
        previous_history = list(mission.history)
        result = self.orchestrator.authorize_mission(mission, envelope, approval, actor=actor)
        if self.repository is not None:
            try:
                self.repository.save_authorized_mission(result, envelope, approval, actor=actor)
            except Exception:
                mission.status = previous_status
                mission.authorization_id = previous_authorization_id
                mission.history = previous_history
                raise
        self._authorization_cache[envelope.envelope_id] = envelope
        self._approval_cache[approval.approval_id] = approval
        return result

    def start_mission(self, mission: Mission, *, actor: str = "master") -> Mission:
        if not mission.authorization_id:
            raise PolicyViolation("Mission has no authorization envelope.")
        self._trusted_authorization(mission.project_id, mission.authorization_id)
        previous_history = list(mission.history)
        previous_status = mission.status
        transition(mission, MissionStatus.RUNNING, actor=actor,
                   reason="Mission execution started within approved scope.")
        try:
            if self.repository is not None:
                self.repository.save_mission(mission, actor=actor)
        except Exception:
            mission.status = previous_status
            mission.history = previous_history
            raise
        return mission

    def add_blocker(self, mission: Mission, reason: str, *, actor: str = "system") -> Mission:
        if not reason.strip():
            raise ValueError("Blocker reason must not be empty.")
        previous_status, previous_history = mission.status, list(mission.history)
        added = reason not in mission.blockers
        if added:
            mission.blockers.append(reason)
        if mission.status in {MissionStatus.AUTHORIZED, MissionStatus.RUNNING}:
            transition(mission, MissionStatus.BLOCKED, actor=actor, reason=reason)
        try:
            if self.repository is not None:
                self.repository.save_mission(mission, actor=actor)
        except Exception:
            mission.status = previous_status
            mission.history = previous_history
            if added:
                mission.blockers.remove(reason)
            raise
        return mission

    def clear_blocker(self, mission: Mission, reason: str, *, actor: str = "master") -> Mission:
        if reason not in mission.blockers:
            return mission
        previous_status, previous_history = mission.status, list(mission.history)
        if mission.status == MissionStatus.BLOCKED and len(mission.blockers) == 1:
            if not mission.authorization_id:
                raise PolicyViolation("Blocked mission has no authorization envelope.")
            self._trusted_authorization(mission.project_id, mission.authorization_id)
        mission.blockers.remove(reason)
        if mission.status == MissionStatus.BLOCKED and not mission.blockers:
            transition(mission, MissionStatus.RUNNING, actor=actor,
                       reason="All recorded blockers have been resolved.")
        try:
            if self.repository is not None:
                self.repository.save_mission(mission, actor=actor)
        except Exception:
            mission.status = previous_status
            mission.history = previous_history
            mission.blockers.append(reason)
            raise
        return mission

    def save_asset(self, envelope: AuthorizationEnvelope, asset: Asset,
                   *, actor: str = "mapper") -> Asset:
        trusted_envelope, _ = self._trusted_authorization(
            envelope.project_id, envelope.envelope_id)
        if authorization_digest(trusted_envelope) != authorization_digest(envelope):
            raise PolicyViolation("Asset envelope does not match the stored signed authorization.")
        classify_discovered_asset(asset, trusted_envelope)
        project = self.get_project(envelope.project_id)
        if self.repository is not None:
            self.repository.save_asset(envelope.project_id, asset, actor=actor)
        project.assets[asset.asset_id] = asset
        return asset

    def save_evidence(self, evidence: EvidenceRecord, *, actor: str = "collector") -> None:
        mission = self.get_mission(evidence.project_id, evidence.mission_id)
        self.attach_evidence(mission, evidence, actor=actor)

    def attach_evidence(self, mission: Mission, evidence: EvidenceRecord,
                        *, actor: str = "collector") -> Mission:
        if evidence.project_id != mission.project_id or evidence.mission_id != mission.mission_id:
            raise PolicyViolation("Evidence project/mission reference does not match.")
        if mission.status not in {MissionStatus.AUTHORIZED, MissionStatus.RUNNING,
                                  MissionStatus.BLOCKED, MissionStatus.EVIDENCE_REVIEW}:
            raise PolicyViolation("Evidence cannot be attached to a mission outside its active review lifecycle.")
        if not mission.authorization_id or evidence.authorization_id != mission.authorization_id:
            raise PolicyViolation("Evidence is not bound to the mission authorization envelope.")
        validate_evidence(evidence)
        envelope, mission_approval = self._trusted_authorization(
            mission.project_id, mission.authorization_id, now=evidence.observed_at)
        locator = evidence.metadata.get("locator")
        method = str(evidence.metadata.get("method", evidence.collection_method)).strip().lower()
        allowed_methods = {item.lower() for item in envelope.allowed_methods}
        if locator is None and (method in allowed_methods or method in HIGH_RISK_METHODS):
            raise PolicyViolation("Target-facing evidence must identify its exact authorized locator.")
        if locator is not None:
            allowed = {item.lower() for item in envelope.allowed_methods}
            prohibited = {item.lower() for item in envelope.prohibited_methods}
            if (not method or method in prohibited or method not in allowed
                    or not asset_is_in_scope(str(locator), envelope.rules)):
                raise PolicyViolation("Evidence locator/method is outside the signed authorization envelope.")
            action_approval_id = evidence.metadata.get("action_approval_id")
            if method in HIGH_RISK_METHODS and not action_approval_id:
                raise PolicyViolation("High-risk evidence requires its action_approval_id.")
            if action_approval_id:
                if self.repository is not None:
                    action_approval = self.repository.get_approval(mission.project_id, str(action_approval_id))
                else:
                    action_approval = self._approval_cache.get(str(action_approval_id))
                expected_action = capability_action_digest(envelope, str(locator), method)
                if (not self.enforcer.validate_approval(action_approval, expected_action, None,
                        now=evidence.observed_at)
                        or action_approval is None or action_approval.expires_at is None
                        or action_approval.expires_at > envelope.expires_at):
                    raise PolicyViolation("Evidence action approval is invalid for the exact locator/method.")
        elif "method" in evidence.metadata:
            raise PolicyViolation("Evidence method metadata requires a locator.")
        project = self.get_project(mission.project_id)
        satisfies = evidence.metadata.get("satisfies", [evidence.kind])
        if not isinstance(satisfies, list) or not all(isinstance(item, str) for item in satisfies):
            raise ValueError("Evidence metadata.satisfies must be a list of strings.")
        previous_completed = set(mission.completed_evidence)
        mission.completed_evidence.update(set(satisfies) & mission.required_evidence)
        if self.repository is not None:
            self.repository.save_evidence(evidence, actor=actor)
            try:
                self.repository.save_mission(mission, actor=actor)
            except Exception:
                mission.completed_evidence = previous_completed
                raise
        project.evidence[evidence.evidence_id] = evidence
        return mission

    def save_finding(self, finding: Finding, *, actor: str = "analyst") -> None:
        project = self.get_project(finding.project_id)
        if finding.status in {FindingStatus.VALIDATED, FindingStatus.ACCEPTED}:
            if self.repository is not None:
                linked = {}
                for evidence_id in finding.evidence_ids:
                    try:
                        linked[evidence_id] = self.repository.get_evidence(
                            finding.project_id, evidence_id)
                    except KeyError:
                        continue
            else:
                linked = {eid: project.evidence[eid] for eid in finding.evidence_ids
                          if eid in project.evidence}
            validate_finding(deepcopy(finding), linked)
        if self.repository is not None:
            self.repository.save_finding(finding, actor=actor)
        project.findings[finding.finding_id] = finding

    def request_evidence_review(self, mission: Mission, *, actor: str = "master") -> Mission:
        previous_status, previous_history = mission.status, list(mission.history)
        transition(mission, MissionStatus.EVIDENCE_REVIEW, actor=actor,
                   reason="Mission submitted for independent evidence sufficiency review.")
        try:
            if self.repository is not None:
                self.repository.save_mission(mission, actor=actor)
        except Exception:
            mission.status = previous_status
            mission.history = previous_history
            raise
        return mission

    def _load_validation_inputs(self, mission: Mission):
        project = self.get_project(mission.project_id)
        if self.repository is not None:
            if not self.repository.store.verify_project_integrity(mission.project_id):
                raise PolicyViolation("Project persistence integrity check failed.")
            evidence = {item.evidence_id: item
                        for item in self.repository.list_evidence(mission.project_id)
                        if item.mission_id == mission.mission_id}
            findings = [item for item in self.repository.list_findings(mission.project_id)
                        if set(item.evidence_ids) & set(evidence)]
        else:
            evidence = {key: value for key, value in project.evidence.items()
                        if value.mission_id == mission.mission_id}
            findings = [item for item in project.findings.values()
                        if set(item.evidence_ids) & set(evidence)]
        for record in evidence.values():
            validate_evidence(record)
        return evidence, findings

    def complete_mission(self, mission: Mission, *, actor: str = "verifier") -> Mission:
        evidence, findings = self._load_validation_inputs(mission)
        checks = validate_mission_closure(mission, evidence, findings)
        failures = [f"{check.code}: {check.detail}" for check in checks if not check.passed]
        if failures:
            raise PolicyViolation("Independent validation failed: " + "; ".join(failures))
        previous_status, previous_history = mission.status, list(mission.history)
        transition(mission, MissionStatus.COMPLETED, actor=actor,
                   reason="Independent evidence validation passed.")
        try:
            if self.repository is not None:
                self.repository.save_mission(mission, actor=actor)
        except Exception:
            mission.status = previous_status
            mission.history = previous_history
            raise
        return mission

    def validate_remediation_plan(self, project_id: str,
                                  actions: list[RemediationAction]) -> None:
        """Validate remediation dependencies and references to accepted findings."""
        if self.repository is not None:
            findings = {item.finding_id: item
                        for item in self.repository.list_findings(project_id)}
        else:
            findings = dict(self.get_project(project_id).findings)
        validate_remediation_graph(actions)
        known_action_ids = {item.action_id for item in actions}
        for action in actions:
            validate_remediation(action, findings, known_action_ids)

    def build_mission_report(self, mission: Mission, *, report_id: str,
                             limitations: tuple[str, ...] = ()) -> ReportBundle:
        """Assemble a report from the mission's stored evidence and finding records."""
        evidence, findings = self._load_validation_inputs(mission)
        return build_report(mission, findings, evidence,
                            report_id=report_id, limitations=limitations)

    def save_case_work_item(self, item: CaseWorkItem, *, actor: str = "master") -> int:
        if self.governance_repository is None:
            raise PolicyViolation("Durable case operations require a configured repository.")
        mission = self.get_mission(item.project_id, item.mission_id)
        if mission.project_id != item.project_id:
            raise PolicyViolation("Case work item does not match its parent mission.")
        return self.governance_repository.save_work_item(item, actor=actor)

    def save_case_timeline_event(self, event: CaseTimelineEvent, *, actor: str = "system") -> int:
        if self.governance_repository is None:
            raise PolicyViolation("Durable case operations require a configured repository.")
        self.get_mission(event.project_id, event.mission_id)
        return self.governance_repository.save_timeline_event(event, actor=actor)

    def save_threat_intel(self, record: ThreatIntelRecord, *, actor: str = "intel-ingest") -> int:
        if self.governance_repository is None:
            raise PolicyViolation("Durable threat-intelligence storage requires a configured repository.")
        return self.governance_repository.save_threat_intel(record, actor=actor)

    def save_remediation_action(self, project_id: str, action: RemediationAction,
                                *, actor: str = "remediation-advisor") -> int:
        if self.governance_repository is None or self.repository is None:
            raise PolicyViolation("Durable remediation storage requires a configured repository.")
        findings = {item.finding_id: item for item in self.repository.list_findings(project_id)}
        for evidence_id in action.verification_evidence_ids:
            try:
                evidence = self.repository.get_evidence(project_id, evidence_id)
            except KeyError as exc:
                raise PolicyViolation(
                    f"Remediation verification evidence does not exist: {evidence_id}") from exc
            if evidence.status.value in {"DISPUTED", "INSUFFICIENT"}:
                raise PolicyViolation(
                    f"Remediation verification evidence is not usable: {evidence_id}")
        return self.governance_repository.save_remediation_action(
            project_id, action, findings, actor=actor)

    def persist_mission_report(self, mission: Mission, *, report_id: str,
                               limitations: tuple[str, ...] = ()) -> ReportBundle:
        if self.governance_repository is None:
            raise PolicyViolation("Durable report storage requires a configured repository.")
        bundle = self.build_mission_report(
            mission, report_id=report_id, limitations=limitations)
        self.governance_repository.save_report(bundle)
        return bundle

    def close_mission(self, mission: Mission, envelope: AuthorizationEnvelope,
                      closure_approval: Approval, *, actor: str = "master") -> Mission:
        if mission.status != MissionStatus.COMPLETED:
            raise PolicyViolation("Only independently validated COMPLETED missions can be closed.")
        if envelope.envelope_id != mission.authorization_id or envelope.project_id != mission.project_id:
            raise PolicyViolation("Closure envelope does not match the mission authorization.")
        if self.repository is not None:
            stored_envelope = self.repository.get_authorization(mission.project_id, mission.authorization_id)
        else:
            stored_envelope = self._authorization_cache.get(mission.authorization_id)
        if (stored_envelope is None
                or authorization_digest(stored_envelope) != authorization_digest(envelope)):
            raise PolicyViolation("Closure envelope does not match the stored authorization record.")
        evidence, findings = self._load_validation_inputs(mission)
        checks = validate_mission_closure(mission, evidence, findings)
        if any(not check.passed for check in checks):
            raise PolicyViolation("Independent validation no longer passes; mission cannot be closed.")
        digest = mission_closure_digest(mission)
        if (not self.enforcer.validate_approval(closure_approval, digest, None)
                or closure_approval.expires_at is None):
            raise PolicyViolation("A valid Ed25519 closure approval bound to this mission is required.")
        previous_status, previous_history = mission.status, list(mission.history)
        transition(mission, MissionStatus.CLOSED, actor=actor,
                   reason="Independent validation passed and Master closure approval verified.")
        try:
            if self.repository is not None:
                self.repository.save_closed_mission(mission, closure_approval, actor=actor)
        except Exception:
            mission.status = previous_status
            mission.history = previous_history
            raise
        return mission

    def delegate_worker(self, task: WorkerTask, mission: Mission,
                        envelope: AuthorizationEnvelope,
                        assets: dict[str, Asset]) -> WorkerAssignment:
        if not mission.authorization_id:
            raise PolicyViolation("Worker parent mission has no authorization envelope.")
        trusted_envelope, _ = self._trusted_authorization(mission.project_id, mission.authorization_id)
        if authorization_digest(trusted_envelope) != authorization_digest(envelope):
            raise PolicyViolation("Worker delegation envelope does not match the stored signed authorization.")
        assignment = self.workers.delegate(task, mission, trusted_envelope, assets)
        if self.repository is not None:
            try:
                self.repository.save_worker_delegation(mission.project_id, task, assignment)
                self._worker_project_ids[task.task_id] = mission.project_id
            except Exception:
                self.workers.revoke(task.task_id, actor="system",
                                    reason="persistence failed; delegation revoked")
                raise
        return assignment

    def _restore_worker_assignment(self, task_id: str) -> tuple[str, WorkerAssignment]:
        if task_id in self._worker_project_ids:
            return self._worker_project_ids[task_id], self.workers.get(task_id)
        if self.repository is None:
            return "", self.workers.get(task_id)
        for project in self.repository.list_projects():
            try:
                assignment = self.repository.get_worker_assignment(project.project_id, task_id)
            except KeyError:
                continue
            self.workers.restore(assignment)
            self._worker_project_ids[task_id] = project.project_id
            return project.project_id, assignment
        raise KeyError(task_id)

    def complete_worker_task(self, task_id: str, result: dict) -> WorkerAssignment:
        project_id, _ = self._restore_worker_assignment(task_id)
        previous = deepcopy(self.workers.get(task_id))
        assignment = self.workers.complete(task_id, result)
        if self.repository is not None:
            try:
                self.repository.save_worker_assignment(project_id, assignment, actor="worker")
            except Exception:
                self.workers.restore(previous, replace=True)
                raise
        return assignment

    def revoke_worker_task(self, task_id: str, *, actor: str, reason: str) -> WorkerAssignment:
        project_id, _ = self._restore_worker_assignment(task_id)
        previous = deepcopy(self.workers.get(task_id))
        assignment = self.workers.revoke(task_id, actor=actor, reason=reason)
        if self.repository is not None:
            try:
                self.repository.save_worker_assignment(project_id, assignment, actor=actor)
            except Exception:
                self.workers.restore(previous, replace=True)
                raise
        return assignment

    def authorize_observation(self, envelope: AuthorizationEnvelope | None,
                              locator: str, method: str, *, mission_approval: Approval,
                              action_approval: Approval | None = None,
                              requires_human_approval: bool = False):
        if envelope is None:
            raise PolicyViolation("An authorization envelope is required.")
        trusted_envelope, trusted_approval = self._trusted_authorization(
            envelope.project_id, envelope.envelope_id)
        if (authorization_digest(trusted_envelope) != authorization_digest(envelope)
                or mission_approval.approval_id != trusted_approval.approval_id):
            raise PolicyViolation("Observation authorization does not match the stored signed mission approval.")
        decision = self.orchestrator.authorize_observation(trusted_envelope, locator, method,
            mission_approval=trusted_approval, action_approval=action_approval,
            requires_human_approval=requires_human_approval)
        if (decision.allowed and action_approval is not None and envelope is not None
                and (requires_human_approval or method.strip().lower() in HIGH_RISK_METHODS)):
            self._approval_cache[action_approval.approval_id] = action_approval
            if self.repository is not None:
                self.repository.save_approval(envelope.project_id, action_approval, actor="master")
        return decision

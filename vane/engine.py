"""Public application facade for embedding VANE in a host runtime."""
from vane.core.orchestrator import AssessmentOrchestrator
from copy import deepcopy
from vane.assessment.asset_mapping import classify_discovered_asset
from vane.core.state_machine import transition
from vane.errors import PolicyViolation
from vane.evidence.manager import validate_evidence
from vane.findings.governance import validate_finding
from vane.models import (
    Asset, AuthorizationEnvelope, EvidenceRecord, Finding, FindingStatus, Mission, MissionStatus,
)
from vane.projects.registry import Project, ProjectRegistry
from vane.security.approval import Approval
from vane.security.digests import (authorization_digest, capability_action_digest, mission_closure_digest)
from vane.security.enforcement import SecurityEnforcer
from vane.security.authorization import asset_is_in_scope
from vane.security.policy_engine import HIGH_RISK_METHODS
from vane.storage.repository import SQLiteRepository
from vane.validation.independent import validate_mission_closure
from vane.workers.contracts import WorkerTask
from vane.workers.orchestrator import WorkerAssignment, WorkerOrchestrator


class VaneEngine:
    """Composition root. Persistence and trusted approval verification are injected."""

    def __init__(self, *, enforcer: SecurityEnforcer | None = None,
                 projects: ProjectRegistry | None = None,
                 repository: SQLiteRepository | None = None) -> None:
        self.enforcer = enforcer or SecurityEnforcer()
        self.projects = projects or ProjectRegistry()
        self.repository = repository
        self.orchestrator = AssessmentOrchestrator(self.enforcer)
        self.workers = WorkerOrchestrator()
        self._authorization_cache: dict[str, AuthorizationEnvelope] = {}
        self._approval_cache: dict[str, Approval] = {}

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
        classify_discovered_asset(asset, envelope)
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
        if self.repository is not None:
            envelope = self.repository.get_authorization(mission.project_id, mission.authorization_id)
            mission_approval = self.repository.get_approval(mission.project_id, envelope.approval_id)
        else:
            envelope = self._authorization_cache.get(mission.authorization_id)
            mission_approval = self._approval_cache.get(envelope.approval_id) if envelope else None
        if (envelope is None or mission_approval is None
                or not envelope.is_time_valid(evidence.observed_at)
                or not self.enforcer.validate_approval(mission_approval,
                    authorization_digest(envelope), envelope.approval_id, now=evidence.observed_at)
                or mission_approval.expires_at is None
                or mission_approval.expires_at > envelope.expires_at):
            raise PolicyViolation("Evidence observation is not covered by a valid signed mission approval.")
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

    def close_mission(self, mission: Mission, envelope: AuthorizationEnvelope,
                      closure_approval: Approval, *, actor: str = "master") -> Mission:
        if mission.status != MissionStatus.COMPLETED:
            raise PolicyViolation("Only independently validated COMPLETED missions can be closed.")
        if envelope.envelope_id != mission.authorization_id or envelope.project_id != mission.project_id:
            raise PolicyViolation("Closure envelope does not match the mission authorization.")
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
        assignment = self.workers.delegate(task, mission, envelope, assets)
        if self.repository is not None:
            try:
                self.repository.save_worker_task(mission.project_id, task)
            except Exception:
                self.workers.revoke(task.task_id, actor="system",
                                    reason="persistence failed; delegation revoked")
                raise
        return assignment

    def complete_worker_task(self, task_id: str, result: dict) -> WorkerAssignment:
        return self.workers.complete(task_id, result)

    def authorize_observation(self, envelope: AuthorizationEnvelope | None,
                              locator: str, method: str, *, mission_approval: Approval,
                              action_approval: Approval | None = None,
                              requires_human_approval: bool = False):
        decision = self.orchestrator.authorize_observation(envelope, locator, method,
            mission_approval=mission_approval, action_approval=action_approval,
            requires_human_approval=requires_human_approval)
        if (decision.allowed and action_approval is not None and self.repository is not None
                and envelope is not None and (requires_human_approval or method.strip().lower() in HIGH_RISK_METHODS)):
            self.repository.save_approval(envelope.project_id, action_approval, actor="master")
        return decision

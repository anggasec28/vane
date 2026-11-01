"""Public application facade for embedding VANE in a host runtime."""
from vane.core.orchestrator import AssessmentOrchestrator
from vane.core.state_machine import transition
from vane.errors import PolicyViolation
from vane.evidence.manager import validate_evidence
from vane.models import (
    Asset, AuthorizationEnvelope, EvidenceRecord, Finding, Mission, MissionStatus,
)
from vane.projects.registry import Project, ProjectRegistry
from vane.security.approval import Approval
from vane.security.enforcement import SecurityEnforcer
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

    def register_project(self, project_id: str, name: str, owner: str) -> Project:
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

    def create_mission(self, project_id: str, objective: str) -> Mission:
        project = self.get_project(project_id)
        mission = Mission.create(project_id, objective)
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
                self.repository.save_authorized_mission(result, approval, actor=actor)
            except Exception:
                mission.status = previous_status
                mission.authorization_id = previous_authorization_id
                mission.history = previous_history
                raise
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
        if reason not in mission.blockers:
            mission.blockers.append(reason)
        if mission.status in {MissionStatus.AUTHORIZED, MissionStatus.RUNNING}:
            transition(mission, MissionStatus.BLOCKED, actor=actor, reason=reason)
        try:
            if self.repository is not None:
                self.repository.save_mission(mission, actor=actor)
        except Exception:
            mission.status = previous_status
            mission.history = previous_history
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

    def save_evidence(self, evidence: EvidenceRecord, *, actor: str = "collector") -> None:
        validate_evidence(evidence)
        project = self.get_project(evidence.project_id)
        if self.repository is not None:
            self.repository.save_evidence(evidence, actor=actor)
        project.evidence[evidence.evidence_id] = evidence

    def attach_evidence(self, mission: Mission, evidence: EvidenceRecord,
                        *, actor: str = "collector") -> Mission:
        if evidence.project_id != mission.project_id or evidence.mission_id != mission.mission_id:
            raise PolicyViolation("Evidence project/mission reference does not match.")
        if not mission.authorization_id or evidence.authorization_id != mission.authorization_id:
            raise PolicyViolation("Evidence is not bound to the mission authorization envelope.")
        validate_evidence(evidence)
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

    def complete_mission(self, mission: Mission, *, actor: str = "verifier") -> Mission:
        project = self.get_project(mission.project_id)
        if self.repository is not None:
            evidence = {item.evidence_id: item
                        for item in self.repository.list_evidence(mission.project_id)
                        if item.mission_id == mission.mission_id}
            findings = [item for item in self.repository.list_findings(mission.project_id)]
        else:
            evidence = {key: value for key, value in project.evidence.items()
                        if value.mission_id == mission.mission_id}
            findings = list(project.findings.values())
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

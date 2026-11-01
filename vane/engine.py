"""Public application facade for embedding VANE in a host runtime."""
from vane.core.orchestrator import AssessmentOrchestrator
from vane.models import Asset, AuthorizationEnvelope, EvidenceRecord, Finding, Mission, MissionStatus
from vane.projects.registry import Project, ProjectRegistry
from vane.security.approval import Approval
from vane.security.enforcement import SecurityEnforcer
from vane.security.policy_engine import HIGH_RISK_METHODS
from vane.storage.repository import SQLiteRepository
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

    def save_evidence(self, evidence: EvidenceRecord, *, actor: str = "collector") -> None:
        if self.repository is None:
            raise RuntimeError("Durable evidence storage is not configured.")
        self.repository.save_evidence(evidence, actor=actor)

    def save_finding(self, finding: Finding, *, actor: str = "analyst") -> None:
        if self.repository is None:
            raise RuntimeError("Durable finding storage is not configured.")
        self.repository.save_finding(finding, actor=actor)

    def delegate_worker(self, task: WorkerTask, mission: Mission,
                        envelope: AuthorizationEnvelope, assets: dict[str, Asset]) -> WorkerAssignment:
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

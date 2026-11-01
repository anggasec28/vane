"""Public application facade for embedding VANE in a host runtime."""
from vane.core.orchestrator import AssessmentOrchestrator
from vane.models import AuthorizationEnvelope, EvidenceRecord, Finding, Mission
from vane.projects.registry import Project, ProjectRegistry
from vane.security.enforcement import SecurityEnforcer
from vane.storage.repository import SQLiteRepository

class VaneEngine:
    """Composition root. Persistence and trusted approval verification are injected."""
    def __init__(self, *, enforcer: SecurityEnforcer | None = None,
                 projects: ProjectRegistry | None = None,
                 repository: SQLiteRepository | None = None) -> None:
        self.enforcer = enforcer or SecurityEnforcer()
        self.projects = projects or ProjectRegistry()
        self.repository = repository
        self.orchestrator = AssessmentOrchestrator(self.enforcer)

    def register_project(self, project_id: str, name: str, owner: str) -> Project:
        if self.repository is not None:
            try:
                self.repository.get_project(project_id)
            except KeyError:
                pass
            else:
                raise ValueError(f"Project already exists: {project_id}")
        project = Project(project_id, name, owner)
        self.projects.add(project)
        if self.repository is not None:
            self.repository.save_project(project)
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
        project.missions[mission.mission_id] = mission
        if self.repository is not None:
            self.repository.save_mission(mission)
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
        result = self.orchestrator.submit_for_approval(mission, actor=actor)
        if self.repository is not None:
            self.repository.save_mission(result, actor=actor)
        return result

    def authorize_mission(self, mission: Mission, envelope: AuthorizationEnvelope,
                          approval, *, actor: str = "master") -> Mission:
        result = self.orchestrator.authorize_mission(mission, envelope, approval, actor=actor)
        if self.repository is not None:
            self.repository.save_mission(result, actor=actor)
        return result

    def save_evidence(self, evidence: EvidenceRecord, *, actor: str = "collector") -> None:
        if self.repository is None:
            raise RuntimeError("Durable evidence storage is not configured.")
        self.repository.save_evidence(evidence, actor=actor)

    def save_finding(self, finding: Finding, *, actor: str = "analyst") -> None:
        if self.repository is None:
            raise RuntimeError("Durable finding storage is not configured.")
        self.repository.save_finding(finding, actor=actor)

    def authorize_observation(self, envelope: AuthorizationEnvelope | None,
                              locator: str, method: str):
        return self.orchestrator.authorize_observation(envelope, locator, method)

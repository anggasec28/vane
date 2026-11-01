"""Public application facade for embedding VANE in a host runtime."""
from vane.core.orchestrator import AssessmentOrchestrator
from vane.models import AuthorizationEnvelope, Mission
from vane.projects.registry import Project, ProjectRegistry
from vane.security.enforcement import SecurityEnforcer

class VaneEngine:
    """Small composition root; adapters and persistence are injected explicitly."""
    def __init__(self, *, enforcer: SecurityEnforcer | None = None,
                 projects: ProjectRegistry | None = None) -> None:
        self.enforcer = enforcer or SecurityEnforcer()
        self.projects = projects or ProjectRegistry()
        self.orchestrator = AssessmentOrchestrator(self.enforcer)

    def register_project(self, project_id: str, name: str, owner: str) -> Project:
        project = Project(project_id, name, owner)
        self.projects.add(project)
        return project

    def create_mission(self, project_id: str, objective: str) -> Mission:
        project = self.projects.get(project_id)
        mission = Mission.create(project_id, objective)
        project.missions[mission.mission_id] = mission
        return mission

    def submit_mission(self, mission: Mission, *, actor: str = "master") -> Mission:
        return self.orchestrator.submit_for_approval(mission, actor=actor)

    def authorize_mission(self, mission: Mission, envelope: AuthorizationEnvelope,
                          *, actor: str = "master") -> Mission:
        return self.orchestrator.authorize_mission(mission, envelope, actor=actor)

    def authorize_observation(self, envelope: AuthorizationEnvelope | None,
                              locator: str, method: str):
        return self.orchestrator.authorize_observation(envelope, locator, method)

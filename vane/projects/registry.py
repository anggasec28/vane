"""In-memory reference registry; persistence requires an explicit storage adapter."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from vane.models import Asset, EvidenceRecord, Finding, Mission

@dataclass(slots=True)
class Project:
    project_id: str
    name: str
    owner: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    assets: dict[str, Asset] = field(default_factory=dict)
    missions: dict[str, Mission] = field(default_factory=dict)
    findings: dict[str, Finding] = field(default_factory=dict)
    evidence: dict[str, EvidenceRecord] = field(default_factory=dict)

class ProjectRegistry:
    def __init__(self) -> None:
        self._projects: dict[str, Project] = {}
    def add(self, project: Project) -> None:
        if project.project_id in self._projects:
            raise ValueError(f"Project already exists: {project.project_id}")
        self._projects[project.project_id] = project
    def get(self, project_id: str) -> Project:
        return self._projects[project_id]
    def list_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._projects))

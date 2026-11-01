from pathlib import Path
import re

def test_every_skill_has_hermes_frontmatter():
    root = Path(__file__).parents[1] / "skills"
    skill_files = sorted(root.glob("*/SKILL.md"))
    assert len(skill_files) == 13
    names = set()
    for path in skill_files:
        content = path.read_text(encoding="utf-8")
        match = re.match(r"^---\n(.*?)\n---\n", content, re.DOTALL)
        assert match, f"Missing YAML frontmatter: {path}"
        name = re.search(r"^name:\s*([a-z0-9-]+)\s*$", match.group(1), re.MULTILINE)
        description = re.search(r"^description:\s*(.+)$", match.group(1), re.MULTILINE)
        assert name and description, f"Missing skill name/description: {path}"
        assert name.group(1) == path.parent.name
        assert len(description.group(1)) <= 60
        names.add(name.group(1))
    config = (Path(__file__).parents[1] / "config.yaml").read_text(encoding="utf-8")
    for required in ("assessment-orchestrator", "authorization-scope",
                     "mcp-tool-governance", "security-evidence-integrity"):
        assert required in names
        assert f"    - {required}" in config

import json
import pytest
from vane.config import ConfigurationError, load_config

def test_example_configuration_is_fail_closed(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "policy": {"default_decision": "deny", "require_authorization_envelope": True,
                   "require_explicit_method_allowlist": True,
                   "high_risk_methods": ["active_scan", "exploit_validation", "credential_test",
                       "transaction_submit", "state_change", "data_export", "destructive_action"]},
        "mcp": {"default_enabled": False},
        "signing": {"private_key_in_engine": False},
        "approval_verification": {"algorithm": "Ed25519", "fail_closed_if_unavailable": True}
    }), encoding="utf-8")
    assert load_config(path)["policy"]["default_decision"] == "deny"

def test_configuration_rejects_allow_by_default(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"policy": {"default_decision": "allow"},
        "approval_verification": {"algorithm": "Ed25519", "fail_closed_if_unavailable": True}}),
        encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(path)

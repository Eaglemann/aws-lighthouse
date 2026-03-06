from pathlib import Path

import pytest

from aws_lighthouse.policy import PolicyConfigError, ScanPolicy, load_policy_config


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "policy.toml"
    path.write_text(content, encoding="utf-8")
    return path


def test_load_policy_config_round_trips_custom_values(tmp_path):
    path = _write(
        tmp_path,
        """
required_tags = ["Environment", "Owner", "CostCenter"]
cost_anomaly_threshold_pct = 75

[regions]
include = ["us-east-1", "eu-west-1"]

[scans]
security = false
tagging = true
""".strip(),
    )

    policy = load_policy_config(path)

    assert policy.required_tags == ("Environment", "Owner", "CostCenter")
    assert policy.cost_anomaly_threshold_pct == 75.0
    assert policy.regions.include == ("us-east-1", "eu-west-1")
    assert policy.scan_enabled("security") is False
    assert policy.scan_enabled("tagging") is True


def test_load_policy_config_rejects_invalid_toml(tmp_path):
    path = _write(tmp_path, "required_tags = [")

    with pytest.raises(PolicyConfigError, match="TOML parse error"):
        load_policy_config(path)


def test_load_policy_config_rejects_unknown_keys(tmp_path):
    path = _write(tmp_path, 'unknown_key = "value"')

    with pytest.raises(PolicyConfigError, match="Extra inputs are not permitted"):
        load_policy_config(path)


def test_load_policy_config_rejects_overlapping_region_filters(tmp_path):
    path = _write(
        tmp_path,
        """
[regions]
include = ["us-east-1"]
exclude = ["us-east-1"]
""".strip(),
    )

    with pytest.raises(PolicyConfigError, match="overlap"):
        load_policy_config(path)


def test_resolve_regions_rejects_unknown_configured_regions():
    policy = ScanPolicy.model_validate({"regions": {"include": ["us-east-1"]}})

    with pytest.raises(PolicyConfigError, match="not enabled"):
        policy.resolve_regions(["eu-west-1"])


def test_scope_token_is_none_for_default_policy():
    assert ScanPolicy.default().scope_token() is None


def test_scope_token_changes_when_effective_policy_changes():
    policy = ScanPolicy.model_validate({"cost_anomaly_threshold_pct": 75})

    token = policy.scope_token()

    assert token is not None
    assert len(token) == 12


def test_scope_token_ignores_region_filters_when_explicit_region_is_used():
    policy = ScanPolicy.model_validate({"regions": {"include": ["us-east-1"]}})

    assert policy.scope_token(explicit_region="us-west-2") is None

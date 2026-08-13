from unittest.mock import MagicMock

from aws_lighthouse.remediation_executor import execute_remediation_action


def _action(**overrides):
    action = {
        "action_id": "delete_ebs_volume_0",
        "phase": 3,
        "remediation_type": "delete_ebs_volume",
        "resource": "vol-123",
        "label": "Delete EBS Volume",
        "region": "eu-west-1",
        "source": "cost_waste",
    }
    action.update(overrides)
    return action


def test_execute_remediation_action_calls_registered_action_with_region():
    action_fn = MagicMock(return_value=True)

    result = execute_remediation_action(
        _action(), actions={"delete_ebs_volume": action_fn}
    )

    action_fn.assert_called_once_with("vol-123", region="eu-west-1")
    assert result == {"status": "applied", "error": None}


def test_execute_remediation_action_rejects_missing_required_region():
    action_fn = MagicMock(return_value=True)

    result = execute_remediation_action(
        _action(region=None), actions={"delete_ebs_volume": action_fn}
    )

    action_fn.assert_not_called()
    assert result["status"] == "invalid"
    assert "Missing region" in (result["error"] or "")


def test_execute_remediation_action_rejects_unknown_type():
    result = execute_remediation_action(_action(remediation_type="unknown"), actions={})

    assert result["status"] == "invalid"
    assert "Unknown remediation type" in (result["error"] or "")


def test_execute_remediation_action_reports_action_failure():
    result = execute_remediation_action(
        _action(), actions={"delete_ebs_volume": lambda *args, **kwargs: False}
    )

    assert result == {"status": "failed", "error": None}

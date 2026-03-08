from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from aws_lighthouse.tools.remediation import (
    DeleteEBSInput,
    TerminateEC2Input,
    delete_ebs,
    terminate_ec2,
)

MOD = "aws_lighthouse.tools.remediation"


def _client_error(code="InvalidInstanceID.NotFound"):
    return ClientError({"Error": {"Code": code, "Message": ""}}, "Op")


# ── terminate_ec2 ─────────────────────────────────────────────────────────────


def test_terminate_ec2_success():
    ec2 = MagicMock()
    ec2.terminate_instances.return_value = {
        "TerminatingInstances": [{"InstanceId": "i-111"}, {"InstanceId": "i-222"}]
    }
    with patch(f"{MOD}.get_client", return_value=ec2):
        result = terminate_ec2.func(TerminateEC2Input(instance_ids=["i-111", "i-222"]))
    assert "2" in result
    ec2.terminate_instances.assert_called_once_with(InstanceIds=["i-111", "i-222"])


def test_terminate_ec2_api_error_returns_error_string():
    ec2 = MagicMock()
    ec2.terminate_instances.side_effect = _client_error()
    with patch(f"{MOD}.get_client", return_value=ec2):
        result = terminate_ec2.func(TerminateEC2Input(instance_ids=["i-bad"]))
    assert result.startswith("Error:")


# ── delete_ebs ────────────────────────────────────────────────────────────────


def test_delete_ebs_all_success():
    with patch(f"{MOD}.delete_ebs_volume", return_value=True) as mock_del:
        result = delete_ebs.func(
            DeleteEBSInput(volume_ids=["vol-aaa", "vol-bbb", "vol-ccc"])
        )
    assert result == "Deleted 3 volumes."
    assert mock_del.call_count == 3


def test_delete_ebs_partial_failure_continues_remaining_volumes():
    with patch(f"{MOD}.delete_ebs_volume", side_effect=[True, False, True]) as mock_del:
        result = delete_ebs.func(
            DeleteEBSInput(volume_ids=["vol-aaa", "vol-bbb", "vol-ccc"])
        )
    assert mock_del.call_count == 3
    assert "Deleted 2 volumes" in result
    assert "Failed to delete 1" in result
    assert "vol-bbb" in result


def test_delete_ebs_all_fail():
    with patch(f"{MOD}.delete_ebs_volume", return_value=False):
        result = delete_ebs.func(DeleteEBSInput(volume_ids=["vol-x", "vol-y"]))
    assert "Deleted 0 volumes" in result
    assert "Failed to delete 2" in result


def test_delete_ebs_volume_failure_reported_in_failed_list():
    # When delete_ebs_volume returns False (e.g. client error or API error),
    # the volume appears in the failed list rather than stopping the batch.
    with patch(f"{MOD}.delete_ebs_volume", return_value=False):
        result = delete_ebs.func(DeleteEBSInput(volume_ids=["vol-z"]))
    assert "Failed to delete 1" in result
    assert "vol-z" in result


def test_delete_ebs_empty_list_returns_zero():
    with patch(f"{MOD}.delete_ebs_volume") as mock_del:
        result = delete_ebs.func(DeleteEBSInput(volume_ids=[]))
    assert result == "Deleted 0 volumes."
    mock_del.assert_not_called()

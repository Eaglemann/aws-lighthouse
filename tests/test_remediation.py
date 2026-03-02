from unittest.mock import MagicMock, patch

from botocore.exceptions import BotoCoreError, ClientError

from aws_lighthouse.tools.remediation import (
    DeleteEBSInput,
    TerminateEC2Input,
    delete_ebs,
    terminate_ec2,
)

MOD = "aws_lighthouse.tools.remediation"


def _client_error(code="VolumeInUse"):
    return ClientError({"Error": {"Code": code, "Message": ""}}, "DeleteVolume")


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
    ec2.terminate_instances.side_effect = _client_error("InvalidInstanceID.NotFound")
    with patch(f"{MOD}.get_client", return_value=ec2):
        result = terminate_ec2.func(TerminateEC2Input(instance_ids=["i-bad"]))
    assert result.startswith("Error:")


# ── delete_ebs ────────────────────────────────────────────────────────────────


def test_delete_ebs_all_success():
    ec2 = MagicMock()
    with patch(f"{MOD}.get_client", return_value=ec2):
        result = delete_ebs.func(
            DeleteEBSInput(volume_ids=["vol-aaa", "vol-bbb", "vol-ccc"])
        )
    assert result == "Deleted 3 volumes."
    assert ec2.delete_volume.call_count == 3


def test_delete_ebs_partial_failure_continues_remaining_volumes():
    ec2 = MagicMock()
    ec2.delete_volume.side_effect = [
        None,  # vol-aaa succeeds
        _client_error("VolumeInUse"),  # vol-bbb fails
        None,  # vol-ccc succeeds
    ]
    with patch(f"{MOD}.get_client", return_value=ec2):
        result = delete_ebs.func(
            DeleteEBSInput(volume_ids=["vol-aaa", "vol-bbb", "vol-ccc"])
        )
    # All three volumes were attempted
    assert ec2.delete_volume.call_count == 3
    assert "Deleted 2 volumes" in result
    assert "Failed to delete 1" in result
    assert "vol-bbb" in result


def test_delete_ebs_all_fail():
    ec2 = MagicMock()
    ec2.delete_volume.side_effect = _client_error("VolumeInUse")
    with patch(f"{MOD}.get_client", return_value=ec2):
        result = delete_ebs.func(DeleteEBSInput(volume_ids=["vol-x", "vol-y"]))
    assert "Deleted 0 volumes" in result
    assert "Failed to delete 2" in result


def test_delete_ebs_client_init_error_returns_error_string():
    with patch(f"{MOD}.get_client", side_effect=BotoCoreError()):
        result = delete_ebs.func(DeleteEBSInput(volume_ids=["vol-z"]))
    assert result.startswith("Error:")


def test_delete_ebs_empty_list_returns_zero():
    ec2 = MagicMock()
    with patch(f"{MOD}.get_client", return_value=ec2):
        result = delete_ebs.func(DeleteEBSInput(volume_ids=[]))
    assert result == "Deleted 0 volumes."
    ec2.delete_volume.assert_not_called()

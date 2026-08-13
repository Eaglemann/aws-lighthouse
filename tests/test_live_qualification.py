from unittest.mock import MagicMock

import pytest

from aws_lighthouse.live_qualification import (
    LiveQualificationError,
    load_aws_live_config,
    verify_expected_aws_identity,
)


def test_live_config_fails_closed_without_explicit_opt_in():
    with pytest.raises(LiveQualificationError, match="AWS_LIGHTHOUSE_LIVE_AWS=1"):
        load_aws_live_config({})


def test_live_config_requires_explicit_profile_and_sandbox_account():
    with pytest.raises(LiveQualificationError, match="AWS_PROFILE"):
        load_aws_live_config(
            {
                "AWS_LIGHTHOUSE_LIVE_AWS": "1",
                "AWS_LIGHTHOUSE_EXPECTED_ACCOUNT_ID": "123456789012",
            }
        )

    with pytest.raises(LiveQualificationError, match="12-digit"):
        load_aws_live_config(
            {
                "AWS_LIGHTHOUSE_LIVE_AWS": "1",
                "AWS_PROFILE": "lighthouse-sandbox",
                "AWS_LIGHTHOUSE_EXPECTED_ACCOUNT_ID": "production",
            }
        )


def test_live_config_parses_regions_and_strictness():
    config = load_aws_live_config(
        {
            "AWS_LIGHTHOUSE_LIVE_AWS": "1",
            "AWS_PROFILE": "lighthouse-sandbox",
            "AWS_LIGHTHOUSE_EXPECTED_ACCOUNT_ID": "123456789012",
            "AWS_LIGHTHOUSE_LIVE_REGIONS": "eu-west-1, us-east-1,eu-west-1",
            "AWS_LIGHTHOUSE_ALLOW_PARTIAL": "1",
        }
    )

    assert config.profile == "lighthouse-sandbox"
    assert config.expected_account_id == "123456789012"
    assert config.regions == ("eu-west-1", "us-east-1")
    assert config.allow_partial_permissions is True


def test_identity_verification_rejects_wrong_account():
    session = MagicMock()
    session.client.return_value.get_caller_identity.return_value = {
        "Account": "999999999999",
        "Arn": "arn:aws:iam::999999999999:user/test",
    }

    with pytest.raises(LiveQualificationError, match="account mismatch"):
        verify_expected_aws_identity(session, "123456789012")

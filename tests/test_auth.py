"""Tests for AuthManager and get_client helpers (auth.py)."""

from unittest.mock import MagicMock, patch

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from aws_lighthouse.auth import AuthManager, get_client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session(arn: str = "arn:aws:iam::123456789012:user/test") -> MagicMock:
    """Return a mock boto3.Session whose STS client resolves successfully."""
    session = MagicMock(spec=boto3.Session)
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Arn": arn, "Account": "123456789012"}
    session.client.return_value = sts
    return session


def _failing_session(exc: Exception) -> MagicMock:
    """Return a mock boto3.Session whose STS client raises exc."""
    session = MagicMock(spec=boto3.Session)
    sts = MagicMock()
    sts.get_caller_identity.side_effect = exc
    session.client.return_value = sts
    return session


# ---------------------------------------------------------------------------
# AuthManager.get_session — caching
# ---------------------------------------------------------------------------


class TestGetSession:
    def test_returns_session_on_first_call(self):
        manager = AuthManager()
        good = _make_session()
        with (
            patch("boto3.Session", return_value=good),
            patch("aws_lighthouse.auth.logger"),
        ):
            session = manager.get_session()
        assert session is good

    def test_session_cached_on_second_call(self):
        manager = AuthManager()
        good = _make_session()
        with (
            patch("boto3.Session", return_value=good),
            patch("aws_lighthouse.auth.logger"),
        ):
            s1 = manager.get_session()
            s2 = manager.get_session()
        assert s1 is s2
        # authenticate() hits STS exactly once
        assert good.client.return_value.get_caller_identity.call_count == 1


# ---------------------------------------------------------------------------
# AuthManager.authenticate — implicit credentials path
# ---------------------------------------------------------------------------


class TestAuthenticateImplicit:
    def test_sets_session_on_success(self):
        manager = AuthManager()
        good = _make_session()
        with (
            patch("boto3.Session", return_value=good),
            patch("aws_lighthouse.auth.logger"),
        ):
            manager.authenticate()
        assert manager._session is good

    def test_does_not_prompt_when_env_creds_present(self):
        manager = AuthManager()
        good = _make_session()
        with (
            patch("boto3.Session", return_value=good),
            patch("aws_lighthouse.auth.logger"),
            patch("typer.prompt") as mock_prompt,
        ):
            manager.authenticate()
        mock_prompt.assert_not_called()


# ---------------------------------------------------------------------------
# AuthManager.authenticate — interactive fallback
# ---------------------------------------------------------------------------


class TestAuthenticateFallback:
    def test_falls_back_to_prompt_on_no_credentials(self):
        manager = AuthManager()
        bad = _failing_session(NoCredentialsError())
        good = _make_session()

        with (
            patch("boto3.Session", side_effect=[bad, good]),
            patch("aws_lighthouse.auth.logger"),
            patch("typer.prompt", side_effect=["my-profile", "us-east-1", ""]),
        ):
            manager.authenticate()

        assert manager._session is good

    def test_falls_back_on_client_error(self):
        manager = AuthManager()
        bad = _failing_session(
            ClientError(
                {"Error": {"Code": "InvalidClientTokenId", "Message": "bad token"}},
                "GetCallerIdentity",
            )
        )
        good = _make_session()

        with (
            patch("boto3.Session", side_effect=[bad, good]),
            patch("aws_lighthouse.auth.logger"),
            patch("typer.prompt", side_effect=["", "us-east-1", ""]),
        ):
            manager.authenticate()

        assert manager._session is good


# ---------------------------------------------------------------------------
# get_client — routing
# ---------------------------------------------------------------------------


class TestGetClient:
    def test_no_region_routes_to_get_aws_client(self):
        mock_client = MagicMock()
        with patch(
            "aws_lighthouse.auth.get_aws_client", return_value=mock_client
        ) as mock:
            result = get_client("ec2")
        mock.assert_called_once_with("ec2")
        assert result is mock_client

    def test_none_region_routes_to_get_aws_client(self):
        mock_client = MagicMock()
        with patch(
            "aws_lighthouse.auth.get_aws_client", return_value=mock_client
        ) as mock:
            result = get_client("iam", region=None)
        mock.assert_called_once_with("iam")
        assert result is mock_client

    def test_with_region_routes_to_get_aws_client_for_region(self):
        mock_client = MagicMock()
        with patch(
            "aws_lighthouse.auth.get_aws_client_for_region", return_value=mock_client
        ) as mock:
            result = get_client("s3", region="eu-west-1")
        mock.assert_called_once_with("s3", "eu-west-1")
        assert result is mock_client

    def test_empty_string_region_treated_as_falsy(self):
        """Empty string region behaves as no-region (falsy check in get_client)."""
        mock_client = MagicMock()
        with patch(
            "aws_lighthouse.auth.get_aws_client", return_value=mock_client
        ) as mock:
            result = get_client("sts", region="")
        mock.assert_called_once_with("sts")
        assert result is mock_client

"""Tests for AuthManager and get_client helpers (auth.py)."""

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import MagicMock, patch

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError

from aws_lighthouse.auth import (
    _RETRY_CONFIG,
    AuthManager,
    auth_manager,
    get_aws_client,
    get_aws_client_for_region,
    get_client,
)

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


class TestGetSessionConcurrent:
    def test_authenticate_called_once_under_concurrent_load(self):
        """10 threads hitting get_session() simultaneously must call authenticate() once."""
        manager = AuthManager()
        good = _make_session()
        barrier = threading.Barrier(10)

        def _get():
            barrier.wait()  # all threads race together
            return manager.get_session()

        with (
            patch("boto3.Session", return_value=good),
            patch("aws_lighthouse.auth.logger"),
        ):
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(_get) for _ in range(10)]
                results = [f.result() for f in as_completed(futures)]

        assert all(r is good for r in results)
        # STS was called exactly once — authenticate() never ran twice
        assert good.client.return_value.get_caller_identity.call_count == 1


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
    def test_no_region_delegates_to_auth_manager(self):
        mock_client = MagicMock()
        with patch.object(auth_manager, "get_client", return_value=mock_client) as mock:
            result = get_client("ec2")
        mock.assert_called_once_with("ec2", None)
        assert result is mock_client

    def test_none_region_delegates_to_auth_manager(self):
        mock_client = MagicMock()
        with patch.object(auth_manager, "get_client", return_value=mock_client) as mock:
            result = get_client("iam", region=None)
        mock.assert_called_once_with("iam", None)
        assert result is mock_client

    def test_with_region_delegates_to_auth_manager(self):
        mock_client = MagicMock()
        with patch.object(auth_manager, "get_client", return_value=mock_client) as mock:
            result = get_client("s3", region="eu-west-1")
        mock.assert_called_once_with("s3", "eu-west-1")
        assert result is mock_client

    def test_empty_string_region_delegates_to_auth_manager(self):
        """Empty string is forwarded as-is; AuthManager.get_client normalises it."""
        mock_client = MagicMock()
        with patch.object(auth_manager, "get_client", return_value=mock_client) as mock:
            result = get_client("sts", region="")
        mock.assert_called_once_with("sts", "")
        assert result is mock_client


# ---------------------------------------------------------------------------
# Retry config — _RETRY_CONFIG is adaptive and applied everywhere
# ---------------------------------------------------------------------------


class TestRetryConfig:
    def test_retry_config_is_adaptive_mode(self):
        assert _RETRY_CONFIG.retries == {"mode": "adaptive"}

    def test_retry_config_is_botocore_config_instance(self):
        assert isinstance(_RETRY_CONFIG, Config)

    def test_get_aws_client_passes_retry_config(self):
        """get_aws_client must forward _RETRY_CONFIG to session.client()."""
        mock_session = MagicMock(spec=boto3.Session)
        mock_session.client.return_value = MagicMock()
        manager = AuthManager()
        manager._session = mock_session
        with patch("aws_lighthouse.auth.auth_manager", manager):
            get_aws_client("ec2")
        mock_session.client.assert_called_once_with("ec2", config=_RETRY_CONFIG)

    def test_get_aws_client_for_region_passes_retry_config(self):
        """get_aws_client_for_region must forward _RETRY_CONFIG to session.client()."""
        mock_session = MagicMock(spec=boto3.Session)
        mock_session.client.return_value = MagicMock()
        manager = AuthManager()
        manager._session = mock_session
        with patch("aws_lighthouse.auth.auth_manager", manager):
            get_aws_client_for_region("s3", "eu-west-1")
        mock_session.client.assert_called_once_with(
            "s3", region_name="eu-west-1", config=_RETRY_CONFIG
        )

    def test_authenticate_passes_retry_config_to_sts(self):
        """The STS validation call inside authenticate() must use _RETRY_CONFIG."""
        manager = AuthManager()
        mock_session = MagicMock(spec=boto3.Session)
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Arn": "arn:aws:iam::123:user/x"}
        mock_session.client.return_value = mock_sts

        with (
            patch("boto3.Session", return_value=mock_session),
            patch("aws_lighthouse.auth.logger"),
        ):
            manager.authenticate()

        mock_session.client.assert_called_once_with("sts", config=_RETRY_CONFIG)


# ---------------------------------------------------------------------------
# Client caching — same key reuses the same client object
# ---------------------------------------------------------------------------


class TestClientCaching:
    def _manager_with_session(self) -> tuple:
        """Return (manager, mock_session) with _session pre-set."""
        manager = AuthManager()
        mock_session = MagicMock(spec=boto3.Session)
        mock_session.client.side_effect = lambda *a, **kw: MagicMock()
        manager._session = mock_session
        return manager, mock_session

    def test_same_key_returns_cached_client(self):
        manager, mock_session = self._manager_with_session()
        c1 = manager.get_client("ec2")
        c2 = manager.get_client("ec2")
        assert c1 is c2
        mock_session.client.assert_called_once()

    def test_different_regions_cached_separately(self):
        manager, mock_session = self._manager_with_session()
        c1 = manager.get_client("ec2", "us-east-1")
        c2 = manager.get_client("ec2", "eu-west-1")
        c3 = manager.get_client("ec2", "us-east-1")  # cache hit
        assert c1 is not c2
        assert c1 is c3
        assert mock_session.client.call_count == 2

    def test_no_region_and_region_cached_separately(self):
        manager, mock_session = self._manager_with_session()
        c1 = manager.get_client("s3")
        c2 = manager.get_client("s3", "ap-southeast-1")
        assert c1 is not c2
        assert mock_session.client.call_count == 2

    def test_empty_string_region_same_key_as_no_region(self):
        manager, mock_session = self._manager_with_session()
        c1 = manager.get_client("sts")
        c2 = manager.get_client("sts", "")
        assert c1 is c2
        mock_session.client.assert_called_once()

    def test_concurrent_same_key_creates_client_once(self):
        manager, mock_session = self._manager_with_session()
        barrier = threading.Barrier(10)

        def _get():
            barrier.wait()
            return manager.get_client("s3", "us-east-1")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_get) for _ in range(10)]
            results = [f.result() for f in as_completed(futures)]

        assert all(r is results[0] for r in results)
        mock_session.client.assert_called_once()


class TestSessionRefresh:
    def test_get_session_refreshes_and_clears_cached_clients_on_expiry(self):
        manager = AuthManager()
        manager._session = MagicMock(spec=boto3.Session)
        manager._clients = {("ec2", None): MagicMock()}
        fresh = MagicMock(spec=boto3.Session)

        with (
            patch.object(manager, "_credentials_expired", side_effect=[True, True]),
            patch.object(manager, "authenticate") as mock_auth,
            patch("aws_lighthouse.auth.logger"),
        ):
            mock_auth.side_effect = lambda: setattr(manager, "_session", fresh)
            session = manager.get_session()

        assert session is fresh
        assert manager._clients == {}
        assert mock_auth.call_count == 1

    def test_get_client_rebuilds_stale_cached_client_after_refresh(self):
        manager = AuthManager()
        stale_client = MagicMock()
        manager._session = MagicMock(spec=boto3.Session)
        manager._clients = {("ec2", None): stale_client}

        fresh_session = MagicMock(spec=boto3.Session)
        fresh_client = MagicMock()
        fresh_session.client.return_value = fresh_client

        with (
            patch.object(
                manager, "_credentials_expired", side_effect=[True, True, False]
            ),
            patch.object(manager, "authenticate") as mock_auth,
            patch("aws_lighthouse.auth.logger"),
        ):
            mock_auth.side_effect = lambda: setattr(manager, "_session", fresh_session)
            client = manager.get_client("ec2")

        assert client is fresh_client
        assert client is not stale_client
        fresh_session.client.assert_called_once_with("ec2", config=_RETRY_CONFIG)

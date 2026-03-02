import threading

import boto3
import typer
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError

from .logger import logger

# Applied to every boto3 client so throttled calls are retried automatically
# instead of silently dropping findings.
_RETRY_CONFIG = Config(retries={"mode": "adaptive"})


class AuthManager:
    """Manages AWS credentials and session initialization for aws-lighthouse."""

    def __init__(self):
        self._session = None
        self._lock = threading.Lock()
        self._clients: dict = {}
        self._clients_lock = threading.Lock()

    def get_session(self) -> boto3.Session:
        """Returns the active boto3 session, authenticating if necessary.

        Uses double-checked locking so concurrent callers (e.g. parallel region
        scans) never call authenticate() more than once.
        """
        if self._session is None:
            with self._lock:
                if self._session is None:
                    self.authenticate()
        return self._session

    def authenticate(self):
        """Detect or prompt for AWS credentials and validate them."""
        logger.action_start("Authenticating with AWS...")

        # 1. Attempt implicit/environment credentials first
        try:
            temp_session = boto3.Session()
            sts = temp_session.client("sts", config=_RETRY_CONFIG)
            identity = sts.get_caller_identity()
            self._session = temp_session
            logger.success(f"Authenticated as {identity['Arn']}")
            return
        except (NoCredentialsError, ClientError):
            pass

        # 2. Fall back to interactive setup
        logger.warn("AWS credentials not found or invalid in environment.")
        logger.step("Let's configure a session for this run.")

        profile_name = typer.prompt(
            "AWS Profile name (leave empty to skip)", default=""
        )
        region_name = typer.prompt("AWS Region", default="us-east-1")
        role_arn = typer.prompt("Role ARN to assume (leave empty to skip)", default="")

        kwargs = {}
        if profile_name:
            kwargs["profile_name"] = profile_name
        if region_name:
            kwargs["region_name"] = region_name

        try:
            session = boto3.Session(**kwargs)

            if role_arn:
                sts_client = session.client("sts", config=_RETRY_CONFIG)
                logger.step(f"Assuming role {role_arn}...")
                assumed_role = sts_client.assume_role(
                    RoleArn=role_arn, RoleSessionName="aws-lighthouse-session"
                )
                credentials = assumed_role["Credentials"]
                session = boto3.Session(
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                    region_name=region_name,
                )

            # Final validation
            sts = session.client("sts", config=_RETRY_CONFIG)
            identity = sts.get_caller_identity()
            self._session = session
            logger.success(f"Successfully authenticated as: {identity['Arn']}")

        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            raise typer.Exit(code=1) from e

    def get_client(self, service_name: str, region: str | None = None):
        """Returns a cached Boto3 client keyed by (service, region).

        Uses double-checked locking so parallel region scans share clients
        instead of creating a new one per call (~250+ instantiations saved on a
        16-region scan).
        """
        key = (service_name, region or None)
        if key not in self._clients:
            with self._clients_lock:
                if key not in self._clients:
                    session = self.get_session()
                    if region:
                        self._clients[key] = session.client(
                            service_name, region_name=region, config=_RETRY_CONFIG
                        )
                    else:
                        self._clients[key] = session.client(
                            service_name, config=_RETRY_CONFIG
                        )
        return self._clients[key]


# Global singleton
auth_manager = AuthManager()


def get_aws_session() -> boto3.Session:
    """Provides the active Boto3 session."""
    return auth_manager.get_session()


def get_aws_client(service_name: str):
    """Provides a cached Boto3 client for a specific service."""
    return auth_manager.get_client(service_name)


def get_aws_client_for_region(service_name: str, region: str):
    """Provides a cached Boto3 client for a specific service in an explicit region."""
    return auth_manager.get_client(service_name, region)


def get_client(service_name: str, region: str | None = None):
    """Provides a cached Boto3 client for a service, optionally in a specific region.

    Prefer this over the bare get_aws_client / get_aws_client_for_region pair
    wherever the region may or may not be present (e.g. scan functions that
    accept an optional region parameter).
    """
    return auth_manager.get_client(service_name, region)

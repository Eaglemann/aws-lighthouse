import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import typer
from .logger import logger


class AuthManager:
    """Manages AWS credentials and session initialization for aws-lighthouse."""

    def __init__(self):
        self._session = None

    def get_session(self) -> boto3.Session:
        """Returns the active boto3 session, authenticating if necessary."""
        if self._session is None:
            self.authenticate()
        return self._session

    def authenticate(self):
        """Detect or prompt for AWS credentials and validate them."""
        logger.action_start("Authenticating with AWS...")

        # 1. Attempt implicit/environment credentials first
        try:
            temp_session = boto3.Session()
            sts = temp_session.client("sts")
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
                sts_client = session.client("sts")
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
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            self._session = session
            logger.success(f"Successfully authenticated as: {identity['Arn']}")

        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            raise typer.Exit(code=1)


# Global singleton
auth_manager = AuthManager()


def get_aws_session() -> boto3.Session:
    """Provides the active Boto3 session."""
    return auth_manager.get_session()


def get_aws_client(service_name: str):
    """Provides a Boto3 client for a specific service."""
    return get_aws_session().client(service_name)

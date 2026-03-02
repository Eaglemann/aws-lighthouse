from botocore.exceptions import BotoCoreError, ClientError
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from ..auth import get_client
from ..logger import logger


class TerminateEC2Input(BaseModel):
    instance_ids: list[str] = Field(
        description="A list of EC2 Instance IDs to terminate. This is a destructive action."
    )


@tool("terminate_ec2")
def terminate_ec2(args: TerminateEC2Input) -> str:
    """Terminates the specified EC2 instances."""
    try:
        ec2 = get_client("ec2")
        response = ec2.terminate_instances(InstanceIds=args.instance_ids)
        term_instances = response.get("TerminatingInstances", [])
        logger.success(
            f"Successfully requested termination for {len(term_instances)} instances."
        )
        return f"Terminated {len(term_instances)} instances."
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to terminate EC2 instances: {str(e)}")
        return f"Error: {str(e)}"


class DeleteEBSInput(BaseModel):
    volume_ids: list[str] = Field(
        description="A list of unused/orphaned EBS Volume IDs to delete. This is a destructive action."
    )


@tool("delete_ebs")
def delete_ebs(args: DeleteEBSInput) -> str:
    """Deletes the specified EBS volumes."""
    deleted: list[str] = []
    failed: list[str] = []
    try:
        ec2 = get_client("ec2")
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to initialise EC2 client: {str(e)}")
        return f"Error: {str(e)}"
    for vid in args.volume_ids:
        try:
            ec2.delete_volume(VolumeId=vid)
            deleted.append(vid)
        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to delete EBS volume {vid}: {str(e)}")
            failed.append(vid)
    if deleted:
        logger.success(f"Successfully deleted {len(deleted)} EBS volumes.")
    if failed:
        return (
            f"Deleted {len(deleted)} volumes. "
            f"Failed to delete {len(failed)}: {', '.join(failed)}"
        )
    return f"Deleted {len(deleted)} volumes."

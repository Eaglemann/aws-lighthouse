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
    except Exception as e:
        logger.error(f"Failed to terminate EC2 instances: {str(e)}")
        return f"Error: {str(e)}"


class DeleteEBSInput(BaseModel):
    volume_ids: list[str] = Field(
        description="A list of unused/orphaned EBS Volume IDs to delete. This is a destructive action."
    )


@tool("delete_ebs")
def delete_ebs(args: DeleteEBSInput) -> str:
    """Deletes the specified EBS volumes."""
    try:
        ec2 = get_client("ec2")
        deleted = 0
        for vid in args.volume_ids:
            ec2.delete_volume(VolumeId=vid)
            deleted += 1
        logger.success(f"Successfully deleted {deleted} EBS volumes.")
        return f"Deleted {deleted} volumes."
    except Exception as e:
        logger.error(f"Failed to delete EBS volumes: {str(e)}")
        return f"Error: {str(e)}"

from botocore.exceptions import BotoCoreError, ClientError
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from ..auth import get_client
from ..logger import logger
from .remediation_actions import delete_ebs_volume


class TerminateEC2Input(BaseModel):
    instance_ids: list[str] = Field(
        description="A list of EC2 Instance IDs to terminate. This is a destructive action."
    )


@tool("terminate_ec2")
def terminate_ec2(args: TerminateEC2Input) -> str:
    """Permanently terminate one or more EC2 instances.

    **IRREVERSIBLE** — terminated instances cannot be restarted. AWS moves
    them through ``shutting-down`` → ``terminated`` states; after a short
    retention window the instance record disappears from the console entirely.

    Storage impact: root EBS volumes whose ``DeleteOnTermination`` flag is
    ``True`` (the default) are deleted along with the instance. Volumes with
    ``DeleteOnTermination=False`` are detached and become available; they must
    be managed separately.  Instance-store volumes are always lost on
    termination.

    Region: both ``terminate_ec2`` and ``get_client("ec2")`` operate in the
    session's default region (no per-call region override). Ensure the active
    AWS session targets the correct region before invoking this tool.

    Returns a summary string indicating how many instances were successfully
    scheduled for termination. On API failure, returns an error string (error
    is also logged).
    """
    try:
        ec2 = get_client("ec2")
        response = ec2.terminate_instances(InstanceIds=args.instance_ids)
        term_instances = response.get("TerminatingInstances", [])
        logger.success(
            f"Successfully requested termination for {len(term_instances)} instances."
        )
        return f"Terminated {len(term_instances)} instances."
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to terminate EC2 instances: {e!s}")
        return f"Error: {e!s}"


class DeleteEBSInput(BaseModel):
    volume_ids: list[str] = Field(
        description="A list of unused/orphaned EBS Volume IDs to delete. This is a destructive action."
    )


@tool("delete_ebs")
def delete_ebs(args: DeleteEBSInput) -> str:
    """Permanently delete one or more EBS volumes.

    **IRREVERSIBLE** — once deleted, the volume and all data stored on it are
    gone. AWS does not provide a restore path for deleted volumes. Snapshots
    previously created from the volume are unaffected and remain available.

    Each volume must be in the ``available`` state (not attached to any
    instance). Volumes in the ``in-use`` state raise a ``ClientError``; those
    IDs are collected in the ``failed`` list and reported in the return string
    without interrupting deletion of the remaining volumes in the batch.

    Region: ``delete_ebs`` and ``get_client("ec2")`` operate in the session's
    default region (no per-call region override). Ensure the active AWS session
    targets the region that contains the volumes before invoking this tool.

    Returns a summary string of the form
    ``"Deleted N volumes."`` on full success or
    ``"Deleted N volumes. Failed to delete M: vol-xxx, ..."`` on partial
    failure. Client initialisation errors return an error string immediately
    before any deletion is attempted.
    """
    deleted: list[str] = []
    failed: list[str] = []
    for vid in args.volume_ids:
        if delete_ebs_volume(vid):
            deleted.append(vid)
        else:
            failed.append(vid)
    if deleted:
        logger.success(f"Successfully deleted {len(deleted)} EBS volumes.")
    if failed:
        return (
            f"Deleted {len(deleted)} volumes. "
            f"Failed to delete {len(failed)}: {', '.join(failed)}"
        )
    return f"Deleted {len(deleted)} volumes."

from typing import List

from ..auth import get_aws_client
from ..logger import logger


def get_enabled_regions() -> List[str]:
    """Return all AWS regions that are enabled (opt-in-not-required or opted-in)."""
    try:
        ec2 = get_aws_client("ec2")
        response = ec2.describe_regions(
            Filters=[
                {
                    "Name": "opt-in-status",
                    "Values": ["opt-in-not-required", "opted-in"],
                }
            ]
        )
        return sorted(r["RegionName"] for r in response.get("Regions", []))
    except Exception as e:
        logger.error(f"Failed to list enabled regions: {e}")
        return []

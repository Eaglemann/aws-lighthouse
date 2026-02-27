from typing import List, Dict, Any
from ..auth import get_aws_client
from ..logger import logger


def get_s3_inventory() -> List[Dict[str, Any]]:
    """List S3 buckets and basic stats."""
    s3 = get_aws_client("s3")
    try:
        response = s3.list_buckets()
        buckets = []
        for bucket in response.get("Buckets", []):
            buckets.append(
                {
                    "BucketName": bucket["Name"],
                    "CreationDate": bucket["CreationDate"].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                }
            )
        return buckets
    except Exception as e:
        logger.error(f"Failed to list S3 buckets: {str(e)}")
        return [{"error": str(e)}]


def get_ec2_inventory() -> List[Dict[str, Any]]:
    """Retrieve all EC2 instances and state."""
    ec2 = get_aws_client("ec2")
    instances = []
    try:
        response = ec2.describe_instances()
        for res in response.get("Reservations", []):
            for inst in res.get("Instances", []):
                # Safely extract Name tag
                name = "Unknown"
                for tag in inst.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]
                        break

                instances.append(
                    {
                        "InstanceId": inst.get("InstanceId"),
                        "Name": name,
                        "Type": inst.get("InstanceType"),
                        "State": inst.get("State", {}).get("Name"),
                        "LaunchTime": inst.get("LaunchTime").strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                        "KeyName": inst.get("KeyName", "None"),
                    }
                )
        return instances
    except Exception as e:
        logger.error(f"Failed to list EC2 instances: {str(e)}")
        return [{"error": str(e)}]


def get_rds_inventory() -> List[Dict[str, Any]]:
    """Retrieve all RDS instances and basic metrics."""
    rds = get_aws_client("rds")
    instances = []
    try:
        response = rds.describe_db_instances()
        for db in response.get("DBInstances", []):
            instances.append(
                {
                    "DBInstanceIdentifier": db.get("DBInstanceIdentifier"),
                    "Engine": db.get("Engine"),
                    "Class": db.get("DBInstanceClass"),
                    "Status": db.get("DBInstanceStatus"),
                    "PubliclyAccessible": db.get("PubliclyAccessible", False),
                }
            )
        return instances
    except Exception as e:
        logger.error(f"Failed to list RDS instances: {str(e)}")
        return [{"error": str(e)}]

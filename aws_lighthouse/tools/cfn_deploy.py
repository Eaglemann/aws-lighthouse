from botocore.exceptions import ClientError
from ..auth import get_aws_session
from ..logger import logger


def deploy_cur_template(
    account_id: str,
    cust_id: str,
    ext_id: str,
    s3_bucket: str,
    template_path: str = "aws_lighthouse/templates/cur.yaml",
) -> bool:
    """Deterministically deploys the CUR template, avoiding LLM hallucinations and timeouts."""

    # 1. Read the template
    try:
        with open(template_path, "r") as f:
            template_body = f.read()
    except FileNotFoundError:
        logger.error(f"Could not find template at {template_path}")
        return False

    # 2. Replace placeholders
    template_body = template_body.replace("{{MANAGEMENT_ACCOUNT_ID}}", account_id)
    template_body = template_body.replace("{{LIGHTHOUSE_ACCOUNT_ID}}", account_id)
    template_body = template_body.replace(
        "{{LIGHTHOUSE_CUSTOMER_RESOURCE_ID}}", cust_id
    )
    template_body = template_body.replace("{{EXTERNAL_ID}}", ext_id)
    template_body = template_body.replace("{{ENABLE_COST_ALLOCATION_BACKFILL}}", "true")

    # Enforce us-east-1 for CUR billing exports, using authenticated session for credentials
    session = get_aws_session()
    s3 = session.client("s3", region_name="us-east-1")
    cfn = session.client("cloudformation", region_name="us-east-1")

    # 3. Create Bucket
    logger.step(f"Creating temporary S3 bucket: {s3_bucket}")
    try:
        s3.create_bucket(Bucket=s3_bucket)
    except ClientError as e:
        if e.response["Error"]["Code"] not in [
            "BucketAlreadyOwnedByYou",
            "BucketAlreadyExists",
        ]:
            logger.error(f"Failed to create bucket: {str(e)}")
            return False

    # 4. Upload Dummy SubAccount Template (satisfies StackSet validation)
    dummy_template = """AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  LighthouseCustomerId:
    Type: String
  LighthouseAccountId:
    Type: String
  ExternalId:
    Type: String
Resources:
  DummyResource:
    Type: AWS::CloudFormation::WaitConditionHandle
"""
    logger.step(
        f"Uploading dummy subaccount template to s3://{s3_bucket}/subaccounts_dummy.yaml"
    )
    try:
        s3.put_object(
            Bucket=s3_bucket,
            Key="subaccounts_dummy.yaml",
            Body=dummy_template.encode("utf-8"),
        )
    except Exception as e:
        logger.error(f"Failed to upload dummy template: {str(e)}")
        return False

    sub_url = f"https://{s3_bucket}.s3.amazonaws.com/subaccounts_dummy.yaml"
    template_body = template_body.replace("{{SUBACCOUNTS_TEMPLATE_URL}}", sub_url)

    # 5. Upload Main Template
    logger.step(f"Uploading rendered template to s3://{s3_bucket}/cur.yaml")
    try:
        s3.put_object(
            Bucket=s3_bucket, Key="cur.yaml", Body=template_body.encode("utf-8")
        )
    except Exception as e:
        logger.error(f"Failed to upload template: {str(e)}")
        return False

    template_url = f"https://{s3_bucket}.s3.amazonaws.com/cur.yaml"

    # 5. Deploy Stack
    stack_name = "lighthouse-cur-deployment"
    logger.step(f"Deploying CloudFormation stack: {stack_name}")
    try:
        cfn.create_stack(
            StackName=stack_name,
            TemplateURL=template_url,
            Capabilities=["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
            Tags=[{"Key": "OwnedBy", "Value": "Lighthouse"}],
        )
        logger.success(f"Successfully initiated stack deployment for {stack_name}!")
        logger.step(
            "Stack creation takes a few minutes. Check the AWS console for progress."
        )
        return True
    except ClientError as e:
        if "AlreadyExistsException" in str(e):
            logger.warn(f"Stack {stack_name} already exists. Attempting update...")
            try:
                cfn.update_stack(
                    StackName=stack_name,
                    TemplateURL=template_url,
                    Capabilities=["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
                    Tags=[{"Key": "OwnedBy", "Value": "Lighthouse"}],
                )
                logger.success(f"Successfully initiated stack update for {stack_name}!")
                return True
            except ClientError as ue:
                if "No updates are to be performed" in str(ue):
                    logger.success("Stack is already up to date.")
                    return True
                logger.error(f"Stack update failed: {str(ue)}")
        else:
            logger.error(f"Stack creation failed: {str(e)}")

        return False

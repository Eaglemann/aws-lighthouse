"""
Tests for deploy_cur_template in aws_lighthouse/tools/cfn_deploy.py.

All AWS calls are mocked — no real credentials or network required.
"""

from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from aws_lighthouse.tools.cfn_deploy import deploy_cur_template

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TEMPLATE_PATH = "aws_lighthouse/templates/cur.yaml"

_CFN_ERROR = ClientError(
    {"Error": {"Code": "ValidationError", "Message": "bad"}}, "CreateStack"
)
_S3_ERROR = ClientError(
    {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "CreateBucket"
)


def _make_s3_mock():
    m = MagicMock()
    m.create_bucket.return_value = {}
    m.put_public_access_block.return_value = {}
    m.put_bucket_encryption.return_value = {}
    m.put_object.return_value = {}
    return m


def _make_cfn_mock():
    m = MagicMock()
    m.create_stack.return_value = {}
    return m


def _patch_clients(s3_mock, cfn_mock):
    """Patch get_client in the cfn_deploy module."""

    def _get_client(service, region):
        return s3_mock if service == "s3" else cfn_mock

    return patch("aws_lighthouse.tools.cfn_deploy.get_client", side_effect=_get_client)


# ---------------------------------------------------------------------------
# Template loading
# ---------------------------------------------------------------------------


def test_returns_false_when_template_not_found():
    with _patch_clients(_make_s3_mock(), _make_cfn_mock()):
        result = deploy_cur_template(
            "123456789",
            "cust-1",
            "ext-1",
            "test-bucket",
            template_path="nonexistent/path.yaml",
        )
    assert result is False


# ---------------------------------------------------------------------------
# Bucket creation failures
# ---------------------------------------------------------------------------


def test_returns_false_on_bucket_creation_error():
    s3 = _make_s3_mock()
    s3.create_bucket.side_effect = ClientError(
        {"Error": {"Code": "InvalidBucketName", "Message": "bad name"}},
        "CreateBucket",
    )
    with _patch_clients(s3, _make_cfn_mock()):
        result = deploy_cur_template(
            "123", "c", "e", "bad-bucket", template_path=_TEMPLATE_PATH
        )
    assert result is False


def test_bucket_already_owned_continues_and_hardens():
    """BucketAlreadyOwnedByYou is idempotent — flow must continue and still harden."""
    s3 = _make_s3_mock()
    s3.create_bucket.side_effect = ClientError(
        {"Error": {"Code": "BucketAlreadyOwnedByYou", "Message": "owned"}},
        "CreateBucket",
    )
    cfn = _make_cfn_mock()
    with _patch_clients(s3, cfn):
        result = deploy_cur_template(
            "123", "c", "e", "my-bucket", template_path=_TEMPLATE_PATH
        )
    assert result is True
    s3.put_public_access_block.assert_called_once()
    s3.put_bucket_encryption.assert_called_once()


# ---------------------------------------------------------------------------
# Bucket hardening
# ---------------------------------------------------------------------------


def test_put_public_access_block_is_called_after_create():
    s3 = _make_s3_mock()
    cfn = _make_cfn_mock()
    with _patch_clients(s3, cfn):
        deploy_cur_template("123", "c", "e", "my-bucket", template_path=_TEMPLATE_PATH)
    s3.put_public_access_block.assert_called_once_with(
        Bucket="my-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )


def test_put_bucket_encryption_is_called_after_bpa():
    s3 = _make_s3_mock()
    cfn = _make_cfn_mock()
    with _patch_clients(s3, cfn):
        deploy_cur_template("123", "c", "e", "my-bucket", template_path=_TEMPLATE_PATH)
    s3.put_bucket_encryption.assert_called_once_with(
        Bucket="my-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )


def test_returns_false_when_put_public_access_block_fails():
    s3 = _make_s3_mock()
    s3.put_public_access_block.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}},
        "PutPublicAccessBlock",
    )
    with _patch_clients(s3, _make_cfn_mock()):
        result = deploy_cur_template(
            "123", "c", "e", "my-bucket", template_path=_TEMPLATE_PATH
        )
    assert result is False
    # Encryption must NOT be attempted if BPA failed
    s3.put_bucket_encryption.assert_not_called()


def test_returns_false_when_put_bucket_encryption_fails():
    s3 = _make_s3_mock()
    s3.put_bucket_encryption.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}},
        "PutBucketEncryption",
    )
    with _patch_clients(s3, _make_cfn_mock()):
        result = deploy_cur_template(
            "123", "c", "e", "my-bucket", template_path=_TEMPLATE_PATH
        )
    assert result is False


# ---------------------------------------------------------------------------
# Stack deployment paths
# ---------------------------------------------------------------------------


def test_successful_stack_creation_returns_true():
    with _patch_clients(_make_s3_mock(), _make_cfn_mock()):
        result = deploy_cur_template(
            "123", "c", "e", "my-bucket", template_path=_TEMPLATE_PATH
        )
    assert result is True


def test_stack_already_exists_update_succeeds_returns_true():
    cfn = _make_cfn_mock()
    cfn.create_stack.side_effect = ClientError(
        {"Error": {"Code": "AlreadyExistsException", "Message": "exists"}},
        "CreateStack",
    )
    cfn.update_stack.return_value = {}
    with _patch_clients(_make_s3_mock(), cfn):
        result = deploy_cur_template(
            "123", "c", "e", "my-bucket", template_path=_TEMPLATE_PATH
        )
    assert result is True
    cfn.update_stack.assert_called_once()


def test_stack_already_exists_no_updates_returns_true():
    cfn = _make_cfn_mock()
    cfn.create_stack.side_effect = ClientError(
        {"Error": {"Code": "AlreadyExistsException", "Message": "exists"}},
        "CreateStack",
    )
    cfn.update_stack.side_effect = ClientError(
        {
            "Error": {
                "Code": "ValidationError",
                "Message": "No updates are to be performed",
            }
        },
        "UpdateStack",
    )
    with _patch_clients(_make_s3_mock(), cfn):
        result = deploy_cur_template(
            "123", "c", "e", "my-bucket", template_path=_TEMPLATE_PATH
        )
    assert result is True


def test_stack_creation_failure_returns_false():
    cfn = _make_cfn_mock()
    cfn.create_stack.side_effect = ClientError(
        {"Error": {"Code": "ValidationError", "Message": "bad template"}},
        "CreateStack",
    )
    with _patch_clients(_make_s3_mock(), cfn):
        result = deploy_cur_template(
            "123", "c", "e", "my-bucket", template_path=_TEMPLATE_PATH
        )
    assert result is False

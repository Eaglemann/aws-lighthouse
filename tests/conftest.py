from botocore.exceptions import ClientError


def make_client_error(code: str, message: str = "test error") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "Operation")

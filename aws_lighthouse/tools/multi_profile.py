import configparser
from pathlib import Path

_AWS_CONFIG_PATH = Path.home() / ".aws" / "config"


def list_aws_profiles(config_path: Path | None = None) -> list[str]:
    """Return named profiles from ~/.aws/config.

    Parses [default] and [profile <name>] sections.  Returns profile names
    (without the 'profile ' prefix).  Returns [] if the file doesn't exist
    or cannot be parsed.
    """
    path = config_path or _AWS_CONFIG_PATH
    if not path.exists():
        return []
    config = configparser.ConfigParser()
    try:
        config.read(str(path))
    except configparser.Error:
        return []
    profiles: list[str] = []
    for section in config.sections():
        if section == "default":
            profiles.append("default")
        elif section.startswith("profile "):
            profiles.append(section[len("profile ") :])
    return profiles

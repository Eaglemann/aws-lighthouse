"""Unit tests for aws_lighthouse/tools/multi_profile.py."""

import configparser
from pathlib import Path

import pytest

from aws_lighthouse.tools.multi_profile import list_aws_profiles

pytestmark = [pytest.mark.unit]


class TestListAwsProfiles:
    def test_returns_named_profiles(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config"
        cfg.write_text(
            "[profile dev]\nregion=us-east-1\n[profile staging]\nregion=us-west-2\n"
        )
        assert list_aws_profiles(cfg) == ["dev", "staging"]

    def test_includes_default_section(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config"
        cfg.write_text("[default]\nregion=us-east-1\n[profile dev]\nregion=us-west-2\n")
        result = list_aws_profiles(cfg)
        assert "default" in result
        assert "dev" in result

    def test_strips_profile_prefix(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config"
        cfg.write_text("[profile my-account]\nregion=eu-west-1\n")
        assert list_aws_profiles(cfg) == ["my-account"]

    def test_returns_empty_when_file_missing(self, tmp_path: Path) -> None:
        assert list_aws_profiles(tmp_path / "nonexistent") == []

    def test_returns_empty_when_no_profiles(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config"
        cfg.write_text("")
        assert list_aws_profiles(cfg) == []

    def test_returns_empty_on_parse_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "config"
        cfg.write_text("[profile dev]\n")

        def bad_read(*args: object, **kwargs: object) -> None:
            raise configparser.Error("bad")

        monkeypatch.setattr(configparser.ConfigParser, "read", bad_read)
        assert list_aws_profiles(cfg) == []

    def test_uses_default_aws_config_path_when_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_path = Path("/does/not/exist/config")
        import aws_lighthouse.tools.multi_profile as mp

        monkeypatch.setattr(mp, "_AWS_CONFIG_PATH", fake_path)
        assert list_aws_profiles() == []

    def test_multiple_profiles_preserves_order(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config"
        cfg.write_text("[profile alpha]\n[profile beta]\n[profile gamma]\n")
        assert list_aws_profiles(cfg) == ["alpha", "beta", "gamma"]

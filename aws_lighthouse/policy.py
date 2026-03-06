import hashlib
import json
import tomllib
from pathlib import Path
from typing import Any, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from .tools.tagging import DEFAULT_REQUIRED_TAGS


class PolicyConfigError(ValueError):
    """Raised when a policy file cannot be parsed or validated."""


class RegionFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()

    @field_validator("include", "exclude", mode="before")
    @classmethod
    def _normalize_regions(cls, value: Any) -> tuple[str, ...]:
        if value in (None, ""):
            return ()
        if not isinstance(value, list | tuple):
            raise TypeError("must be an array of region names")

        regions: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise TypeError("region names must be strings")
            region = item.strip()
            if not region:
                raise ValueError("region names must not be empty")
            if region not in regions:
                regions.append(region)
        return tuple(regions)

    @model_validator(mode="after")
    def _reject_overlap(self) -> Self:
        overlap = sorted(set(self.include) & set(self.exclude))
        if overlap:
            joined = ", ".join(overlap)
            raise ValueError(f"regions.include and regions.exclude overlap: {joined}")
        return self

    def active(self) -> bool:
        return bool(self.include or self.exclude)

    def model_value(self) -> dict[str, list[str]]:
        return {
            "include": list(self.include),
            "exclude": list(self.exclude),
        }


class ScanToggles(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cost_anomalies: bool = True
    ri_sp_coverage: bool = True
    security: bool = True
    iam: bool = True
    cloudwatch: bool = True
    cost_waste: bool = True
    tagging: bool = True


class ScanPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    required_tags: tuple[str, ...] = Field(
        default_factory=lambda: tuple(DEFAULT_REQUIRED_TAGS)
    )
    cost_anomaly_threshold_pct: float = 50.0
    regions: RegionFilters = Field(default_factory=RegionFilters)
    scans: ScanToggles = Field(default_factory=ScanToggles)

    @field_validator("required_tags", mode="before")
    @classmethod
    def _normalize_required_tags(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return tuple(DEFAULT_REQUIRED_TAGS)
        if not isinstance(value, list | tuple):
            raise TypeError("required_tags must be an array of tag keys")

        tags: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise TypeError("tag keys must be strings")
            tag = item.strip()
            if not tag:
                raise ValueError("tag keys must not be empty")
            if tag not in tags:
                tags.append(tag)
        if not tags:
            raise ValueError("required_tags must contain at least one tag key")
        return tuple(tags)

    @field_validator("cost_anomaly_threshold_pct")
    @classmethod
    def _validate_threshold(cls, value: float) -> float:
        threshold = float(value)
        if threshold < 0:
            raise ValueError("cost_anomaly_threshold_pct must be >= 0")
        return threshold

    @classmethod
    def default(cls) -> "ScanPolicy":
        return cls()

    def scan_enabled(self, name: str) -> bool:
        return bool(getattr(self.scans, name))

    def resolve_regions(self, enabled_regions: list[str]) -> list[str]:
        if not self.regions.active():
            return enabled_regions

        configured = set(self.regions.include) | set(self.regions.exclude)
        unknown = sorted(configured - set(enabled_regions))
        if unknown:
            joined = ", ".join(unknown)
            raise PolicyConfigError(
                f"configured regions are not enabled for this account: {joined}"
            )

        selected = enabled_regions
        if self.regions.include:
            include_set = set(self.regions.include)
            selected = [region for region in selected if region in include_set]
        if self.regions.exclude:
            exclude_set = set(self.regions.exclude)
            selected = [region for region in selected if region not in exclude_set]

        if not selected:
            raise PolicyConfigError(
                "configured region filters excluded all enabled regions"
            )
        return selected

    def scope_token(self, *, explicit_region: str | None = None) -> str | None:
        effective = self._effective_scope_payload(explicit_region=explicit_region)
        default_payload = self.default()._effective_scope_payload(
            explicit_region=explicit_region
        )
        if effective == default_payload:
            return None

        encoded = json.dumps(effective, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:12]

    def _effective_scope_payload(
        self, *, explicit_region: str | None = None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"scans": self.scans.model_dump()}
        if self.scan_enabled("cost_anomalies"):
            payload["cost_anomaly_threshold_pct"] = self.cost_anomaly_threshold_pct
        if self.scan_enabled("tagging"):
            payload["required_tags"] = list(self.required_tags)
        if explicit_region is None and self.regions.active():
            payload["regions"] = self.regions.model_value()
        return payload


def load_policy_config(path: Path) -> ScanPolicy:
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise PolicyConfigError(f"policy file not found: {path}") from exc
    except OSError as exc:
        raise PolicyConfigError(f"failed to read policy file: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        line = getattr(exc, "lineno", "?")
        column = getattr(exc, "colno", "?")
        message = getattr(exc, "msg", str(exc))
        raise PolicyConfigError(
            f"TOML parse error at line {line}, column {column}: {message}"
        ) from exc

    try:
        return ScanPolicy.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first.get("loc", ()))
        detail = first.get("msg", "invalid value")
        prefix = f"{location}: " if location else ""
        raise PolicyConfigError(f"{prefix}{detail}") from exc

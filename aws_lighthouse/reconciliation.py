"""Trust-aware scan reconciliation for deltas, baselines, and opportunities."""

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, cast

from .opportunities import SECTION_TO_SOURCE_KIND
from .types import OpportunitySourceKind, ScanError, ScanResult

_REGIONAL_SOURCE_KINDS: frozenset[OpportunitySourceKind] = frozenset(
    {"security", "cloudwatch", "cost_waste", "tagging"}
)


def _canonicalize(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _diff_lists(previous: list[Any], current: list[Any]) -> dict[str, Any]:
    previous_by_key = {_canonicalize(item): item for item in previous}
    current_by_key = {_canonicalize(item): item for item in current}
    previous_keys = set(previous_by_key)
    current_keys = set(current_by_key)
    return {
        "new": [current_by_key[key] for key in sorted(current_keys - previous_keys)],
        "resolved": [
            previous_by_key[key] for key in sorted(previous_keys - current_keys)
        ],
        "unchanged_count": len(previous_keys & current_keys),
    }


def _diff_mappings(
    previous: Mapping[str, Any], current: Mapping[str, Any]
) -> dict[str, Any]:
    new: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    unchanged = 0
    for key in sorted(set(previous) | set(current)):
        if key not in previous:
            new.append({"field": key, "value": current[key]})
            continue
        if key not in current:
            resolved.append({"field": key, "value": previous[key]})
            continue
        if _canonicalize(previous[key]) == _canonicalize(current[key]):
            unchanged += 1
            continue
        new.append({"field": key, "value": current[key], "previous": previous[key]})
        resolved.append({"field": key, "value": previous[key], "current": current[key]})
    return {"new": new, "resolved": resolved, "unchanged_count": unchanged}


def _build_section_delta(previous: Any, current: Any) -> dict[str, Any]:
    if isinstance(previous, list) and isinstance(current, list):
        return _diff_lists(previous, current)
    if isinstance(previous, Mapping) and isinstance(current, Mapping):
        return _diff_mappings(previous, current)
    unchanged = _canonicalize(previous) == _canonicalize(current)
    return {
        "new": [] if unchanged else [current],
        "resolved": [] if unchanged else [previous],
        "unchanged_count": int(unchanged),
    }


def build_delta_payload(
    *,
    baseline_snapshot: dict[str, Any] | None,
    section_results: Mapping[str, ScanResult],
    scope_key: str,
    delta_section_keys: Sequence[str],
) -> dict[str, Any]:
    """Diff scan sections without treating missing evidence as remediation.

    Positive list findings remain reportable during a partial scan. A degraded
    section never emits resolved items because absence is not proof of repair.
    """

    baseline_found = baseline_snapshot is not None
    previous_sections = (
        cast(dict[str, Any], baseline_snapshot.get("data", {}))
        if baseline_snapshot
        else {}
    )
    section_deltas: dict[str, dict[str, Any]] = {}
    degraded_sections: list[str] = []
    total_new = 0
    total_resolved = 0
    sections_with_new: list[str] = []
    sections_with_resolved: list[str] = []
    total_errors = 0

    for section in delta_section_keys:
        result = section_results[section]
        errors = result.get("errors", [])
        degraded = bool(errors)
        total_errors += len(errors)
        if degraded:
            degraded_sections.append(section)

        if not baseline_found:
            delta = {"new": [], "resolved": [], "unchanged_count": 0}
        else:
            previous = previous_sections.get(section)
            current = result.get("data")
            if degraded and not (
                isinstance(previous, list) and isinstance(current, list)
            ):
                delta = {"new": [], "resolved": [], "unchanged_count": 0}
            else:
                delta = _build_section_delta(previous, current)
                if degraded:
                    delta["resolved"] = []

        delta["trusted"] = not degraded
        delta["error_count"] = len(errors)
        section_deltas[section] = delta
        if delta["new"]:
            sections_with_new.append(section)
        if delta["resolved"]:
            sections_with_resolved.append(section)
        total_new += len(cast(list[Any], delta["new"]))
        total_resolved += len(cast(list[Any], delta["resolved"]))

    return {
        "baseline_found": baseline_found,
        "baseline_recorded_at": (
            baseline_snapshot.get("recorded_at") if baseline_snapshot else None
        ),
        "scope_key": scope_key,
        "summary": {
            "total_new": total_new,
            "total_resolved": total_resolved,
            "sections_with_new": sections_with_new,
            "sections_with_resolved": sections_with_resolved,
            "degraded": bool(degraded_sections),
            "degraded_sections": degraded_sections,
            "error_count": total_errors,
        },
        "sections": section_deltas,
    }


def _union_lists(previous: list[Any], current: list[Any]) -> list[Any]:
    merged = {_canonicalize(item): item for item in previous}
    for item in current:
        merged.setdefault(_canonicalize(item), item)
    return list(merged.values())


def build_persistable_snapshot(
    *,
    baseline_snapshot: dict[str, Any] | None,
    section_results: Mapping[str, ScanResult],
) -> dict[str, Any]:
    """Build a baseline that never overwrites trustworthy evidence with gaps."""

    previous_sections = (
        cast(dict[str, Any], baseline_snapshot.get("data", {}))
        if baseline_snapshot
        else {}
    )
    snapshot: dict[str, Any] = {}
    for section, result in section_results.items():
        current = result.get("data")
        if not result.get("errors"):
            snapshot[section] = current
            continue

        previous = previous_sections.get(section)
        if isinstance(previous, list) and isinstance(current, list):
            snapshot[section] = _union_lists(previous, current)
        elif section in previous_sections:
            snapshot[section] = previous
        else:
            snapshot[section] = current
    return snapshot


def source_errors_from_section_results(
    section_results: Mapping[str, ScanResult],
    *,
    region_discovery_errors: Sequence[ScanError] = (),
    enabled_source_kinds: Iterable[OpportunitySourceKind] = (),
) -> dict[OpportunitySourceKind, list[ScanError]]:
    """Map tracked section failures onto opportunity resolution scopes."""

    source_errors: dict[OpportunitySourceKind, list[ScanError]] = {}
    for section, source_kind in SECTION_TO_SOURCE_KIND.items():
        result = section_results.get(section)
        if result and result.get("errors"):
            source_errors[source_kind] = list(result["errors"])
    if region_discovery_errors:
        for source_kind in enabled_source_kinds:
            if source_kind in _REGIONAL_SOURCE_KINDS:
                source_errors.setdefault(source_kind, []).extend(
                    region_discovery_errors
                )
    return source_errors

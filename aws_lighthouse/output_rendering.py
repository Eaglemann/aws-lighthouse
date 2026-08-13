"""Pure formatting and machine-output renderers shared by CLI entry points."""

import re
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .types import RemediationAction, RemediationPlan

_SEV_STYLE = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold blue"}
_SEV_LABEL = {"HIGH": "● HIGH", "MEDIUM": "● MED ", "LOW": "● LOW "}


def severity_text(severity: str) -> Text:
    return Text(
        _SEV_LABEL.get(severity, severity),
        style=_SEV_STYLE.get(severity, "white"),
    )


def resource_count(resources: list[Any]) -> str:
    return str(len(resources))


def percentage_text(value: float | None, low: float = 60.0, high: float = 80.0) -> str:
    if value is None:
        return "[dim]N/A[/dim]"
    color = "green" if value >= high else ("yellow" if value >= low else "red")
    return f"[{color}]{value:.1f}%[/{color}]"


def dollar_text(value: float | None) -> str:
    return f"${value:,.2f}" if value is not None else "[dim]N/A[/dim]"


def scope_label(region: str | None) -> str:
    return region or "global"


def render_remediation_plan(console: Console, plan: RemediationPlan) -> None:
    groups: list[Any] = []
    action_number = 1
    for phase in plan["phases"]:
        color = phase["color"]
        count = len(phase["actions"])
        groups.append(
            Text(
                f"  {phase['title']}  ·  {phase['risk']}  "
                f"({count} action{'s' if count != 1 else ''})",
                style=f"bold {color}",
            )
        )
        phase_table = Table(
            box=box.SIMPLE_HEAD,
            show_header=False,
            padding=(0, 2),
            show_edge=False,
        )
        phase_table.add_column("#", justify="right", style="dim", no_wrap=True)
        phase_table.add_column("Label", no_wrap=True)
        phase_table.add_column("Source", style="dim", no_wrap=True)
        phase_table.add_column("Resource", no_wrap=True)
        for action in phase["actions"]:
            phase_table.add_row(
                str(action_number),
                action["label"],
                action["source"],
                action["resource"],
            )
            action_number += 1
        groups.append(phase_table)
    console.print(
        Panel(
            Group(*groups),
            title="[bold cyan]🔧 Remediation Plan[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    console.print()


def render_remediation_preview(
    console: Console, selections: list[RemediationAction]
) -> None:
    preview = Table(
        box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
    )
    preview.add_column("Action", style="bold cyan", no_wrap=True)
    preview.add_column("Source", style="dim", no_wrap=True)
    preview.add_column("Scope", style="dim", no_wrap=True)
    preview.add_column("Resource", no_wrap=True)
    for action in selections:
        preview.add_row(
            action["label"],
            action["source"],
            scope_label(action["region"]),
            action["resource"],
        )
    console.print(
        Panel(
            preview,
            title="[bold cyan]Remediation Preview[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    console.print()


def _finding_to_rule_id(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:64]


def _rule_id_to_name(rule_id: str) -> str:
    return "".join(part.capitalize() for part in rule_id.split("-"))


def _severity_to_sarif_level(severity: str | None) -> str:
    if severity in ("CRITICAL", "HIGH"):
        return "error"
    if severity == "MEDIUM":
        return "warning"
    if severity == "LOW":
        return "note"
    return "warning"


def _distribution_version() -> str:
    try:
        return version("aws-lighthouse")
    except PackageNotFoundError:
        return "0.0.0+source"


def build_sarif_output(  # noqa: C901
    payloads: dict[str, Any], account_id: str
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from scan payloads."""
    v1 = payloads.get("v1", {})
    raw_findings: list[tuple[str, str, str | None]] = []
    for finding in v1.get("security_findings", []):
        raw_findings.append(
            (
                str(finding.get("finding", "")),
                str(finding.get("resource", "")),
                finding.get("severity"),
            )
        )
    for finding in v1.get("iam_findings", []):
        raw_findings.append(
            (
                str(finding.get("reason", "")),
                str(finding.get("principal_name", "")),
                finding.get("severity"),
            )
        )
    for finding in v1.get("cost_waste", []):
        raw_findings.append(
            (
                str(finding.get("finding", "")),
                str(finding.get("resource", "")),
                None,
            )
        )
    for finding in v1.get("tagging_findings", []):
        missing = finding.get("missing_tags", [])
        text = (
            "Missing tags: " + ", ".join(missing)
            if missing
            else "Missing required tags"
        )
        raw_findings.append((text, str(finding.get("resource_id", "")), None))
    for finding in v1.get("cloudwatch_findings", []):
        missing = finding.get("missing_alarms", [])
        text = (
            "Missing alarms: " + ", ".join(missing)
            if missing
            else "Missing CloudWatch alarms"
        )
        raw_findings.append((text, str(finding.get("resource_id", "")), None))
    for finding in v1.get("compute_optimizer", []):
        text = (
            f"EC2 rightsizing: {finding.get('current_type', '')} -> "
            f"{finding.get('recommended_type', '')} "
            f"(saves ${finding.get('estimated_monthly_savings_usd', 0):.2f}/mo)"
        )
        raw_findings.append((text, str(finding.get("instance_id", "")), None))
    for finding in v1.get("tag_cost_coverage", []):
        if finding.get("untagged_pct", 0) > 20:
            text = (
                f"Tag '{finding['tag_key']}' missing on "
                f"{finding['untagged_pct']:.1f}% of spend"
                f" (${finding['untagged_usd']:.2f} untagged)"
            )
            raw_findings.append((text, finding["tag_key"], None))

    seen_rules: dict[str, dict[str, Any]] = {}
    for finding_text, _, severity in raw_findings:
        rule_id = _finding_to_rule_id(finding_text)
        if rule_id and rule_id not in seen_rules:
            seen_rules[rule_id] = {
                "id": rule_id,
                "name": _rule_id_to_name(rule_id),
                "shortDescription": {"text": finding_text},
                "defaultConfiguration": {"level": _severity_to_sarif_level(severity)},
            }

    results: list[dict[str, Any]] = []
    for finding_text, resource_id, severity in raw_findings:
        rule_id = _finding_to_rule_id(finding_text)
        if not rule_id:
            continue
        results.append(
            {
                "ruleId": rule_id,
                "level": _severity_to_sarif_level(severity),
                "message": {"text": finding_text},
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "name": resource_id,
                                "kind": "aws-resource",
                                "fullyQualifiedName": (
                                    f"aws://{account_id}/{resource_id}"
                                ),
                            }
                        ]
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aws-lighthouse",
                        "version": _distribution_version(),
                        "informationUri": (
                            "https://github.com/Eaglemann/aws-lighthouse"
                        ),
                        "rules": list(seen_rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

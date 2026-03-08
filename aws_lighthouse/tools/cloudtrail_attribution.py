"""
CloudTrail cost attribution — correlates Cost Explorer anomalies with
CloudTrail API call history to surface the IAM actor responsible for
resource activity in the anomalous window.
"""

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger
from ..scan_contract import error_result, ok_result, scan_error_from_exception
from ..types import CostAnomaly, CostAttribution, CostAttributionEvent, ScanResult

# Maps CE service display names → CloudTrail event names to query.
# lookup_events only accepts ONE LookupAttribute per call, so each event
# name requires its own API call.
_SERVICE_EVENTS: dict[str, list[str]] = {
    "Amazon EC2": ["RunInstances", "CreateVolume", "AllocateAddress"],
    "AWS Lambda": ["CreateFunction20150331", "UpdateFunctionCode20150331v2"],
    "Amazon RDS": ["CreateDBInstance", "RestoreDBInstanceFromDBSnapshot"],
    "Amazon S3": ["CreateBucket", "PutObject"],
    "Amazon DynamoDB": ["CreateTable", "RestoreTableFromBackup"],
    "Amazon EKS": ["CreateCluster", "CreateNodegroup"],
    "Amazon ECS": ["CreateService", "RunTask"],
    "AWS Glue": ["CreateJob", "StartJobRun"],
    "Amazon EMR": ["RunJobFlow"],
    "Amazon Redshift": ["CreateCluster", "RestoreFromClusterSnapshot"],
    "Amazon ElastiCache": ["CreateCacheCluster", "CreateReplicationGroup"],
    "Amazon SageMaker": ["CreateTrainingJob", "CreateEndpoint"],
    "AWS Batch": ["SubmitJob", "RegisterJobDefinition"],
    "Amazon OpenSearch Service": ["CreateDomain"],
    "AWS Fargate": ["RunTask"],
    "Amazon Kinesis": ["CreateStream", "StartStreamEncryption"],
}


def _extract_actor(detail_str: str) -> str:
    """Extract a human-readable actor name from a CloudTrail CloudTrailEvent JSON string."""
    try:
        detail = json.loads(detail_str)
        identity = detail.get("userIdentity", {})
        id_type = identity.get("type", "")
        if id_type == "IAMUser":
            return str(identity["userName"])
        if id_type == "AssumedRole":
            return str(identity["sessionContext"]["sessionIssuer"]["userName"])
        if id_type == "Root":
            return "root"
        if id_type == "AWSService":
            return str(identity.get("invokedBy", "unknown"))
    except (KeyError, json.JSONDecodeError):
        pass
    return "unknown"


def _lookup_events_for_name(
    ct: object,
    event_name: str,
    start_time: datetime,
    end_time: datetime,
    max_events: int,
) -> list[dict]:
    """
    Fetch CloudTrail events for one EventName using a manual NextToken loop.

    CloudTrail lookup_events does NOT support the paginator interface;
    we loop manually and stop once we have max_events or exhaust pages.
    """
    events: list[dict] = []
    kwargs: dict = {}
    while True:
        resp = ct.lookup_events(  # type: ignore[attr-defined]
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": event_name}
            ],
            StartTime=start_time,
            EndTime=end_time,
            **kwargs,
        )
        events.extend(resp.get("Events", []))
        if "NextToken" not in resp or len(events) >= max_events:
            break
        kwargs["NextToken"] = resp["NextToken"]
    return events


def get_cost_attribution(
    anomalies: list[CostAnomaly],
    lookback_days: int = 30,
    max_events: int = 10,
    region: str | None = None,
) -> ScanResult:
    """
    Correlate Cost Explorer anomalies with CloudTrail API call history.

    For each anomaly whose service is in ``_SERVICE_EVENTS``, issues one
    ``cloudtrail.lookup_events`` call per event name (in parallel via
    ThreadPoolExecutor), merges results, and surfaces the IAM actor
    responsible for each matching API call in the anomalous window.

    Returns ``ok_result(list[CostAttribution])`` — one entry per service
    that has at least one matching CloudTrail event.  Services not present
    in ``_SERVICE_EVENTS`` are silently skipped.
    """
    if not anomalies:
        return ok_result([])

    try:
        ct = get_client("cloudtrail", region)
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to initialise CloudTrail client: {e}")
        return error_result(
            data=[],
            errors=[
                scan_error_from_exception(
                    service="cloudtrail",
                    operation="CreateClient",
                    exc=e,
                )
            ],
        )

    end_time = datetime.now(UTC)
    start_time = end_time - timedelta(days=lookback_days)

    attributions: list[CostAttribution] = []

    try:
        for anomaly in anomalies:
            service = anomaly["service"]
            event_names = _SERVICE_EVENTS.get(service)
            if not event_names:
                continue

            # Fire one lookup call per event name in parallel.
            raw_events: list[dict] = []
            with ThreadPoolExecutor(max_workers=min(len(event_names), 5)) as executor:
                futures = {
                    executor.submit(
                        _lookup_events_for_name,
                        ct,
                        name,
                        start_time,
                        end_time,
                        max_events,
                    ): name
                    for name in event_names
                }
                for future in as_completed(futures):
                    try:
                        raw_events.extend(future.result())
                    except (ClientError, BotoCoreError) as e:
                        logger.error(
                            f"CloudTrail lookup failed for {futures[future]}: {e}"
                        )

            # Sort by EventTime descending, cap at max_events.
            raw_events.sort(
                key=lambda ev: ev.get("EventTime", datetime.min.replace(tzinfo=UTC)),
                reverse=True,
            )
            raw_events = raw_events[:max_events]

            attribution_events: list[CostAttributionEvent] = []
            for ev in raw_events:
                actor = _extract_actor(ev.get("CloudTrailEvent", "{}"))
                raw_time = ev.get("EventTime")
                event_time_str = (
                    raw_time.isoformat()
                    if isinstance(raw_time, datetime)
                    else str(raw_time)
                )
                attribution_events.append(
                    {
                        "event_name": ev.get("EventName", ""),
                        "actor": actor,
                        "event_time": event_time_str,
                        "region": ev.get("AwsRegion", ""),
                    }
                )

            attributions.append(
                {
                    "service": service,
                    "pct_change": anomaly["pct_change"],
                    "events": attribution_events,
                }
            )

    except (ClientError, BotoCoreError) as e:
        logger.error(f"CloudTrail attribution failed: {e}")
        return error_result(
            data=[],
            errors=[
                scan_error_from_exception(
                    service="cloudtrail",
                    operation="LookupEvents",
                    exc=e,
                )
            ],
        )

    return ok_result(attributions)

"""Lambda handler for AWS alerting system.

Turns SNS-delivered AWS events into readable, actionable ntfy notifications:
a short human title, a markdown body with the fields that actually matter,
a priority/tag reflecting real severity, and (where possible) a tap-through
link straight to the relevant AWS console page.

Two message shapes are handled: EventBridge-enveloped events
(`source`/`detail-type`/`detail`) and native CloudWatch Alarm SNS messages
(top-level `AlarmName`/`NewStateValue`/...), since some alarms publish to
SNS directly instead of via EventBridge.
"""

import json
import logging
import os
import zoneinfo
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import quote

import boto3  # pylint: disable=import-error
import urllib3

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

# Cache for container reuse
SSM = None
NTFY_TOKEN = None

AMSTERDAM = zoneinfo.ZoneInfo("Europe/Amsterdam")

PRIORITY_MIN = 1
PRIORITY_LOW = 2
PRIORITY_DEFAULT = 3
PRIORITY_HIGH = 4
PRIORITY_URGENT = 5

CLOUDTRAIL_DETAIL_TYPES = {
    "AWS Console Sign In via CloudTrail",
    "AWS API Call via CloudTrail",
}


@dataclass
class Notification:
    """A fully formatted ntfy notification."""

    title: str
    message: str
    priority: int = PRIORITY_DEFAULT
    tags: str = "bell"
    click: str | None = None


# --- Rendering helpers -----------------------------------------------------


def local_time(raw: str | None) -> str:
    """Render an ISO-8601 UTC timestamp as a Europe/Amsterdam local time string."""
    if not raw:
        return "unknown time"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return raw
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=zoneinfo.ZoneInfo("UTC"))
    return parsed.astimezone(AMSTERDAM).strftime("%d-%m-%Y %H:%M:%S")


def bullets(pairs: list[tuple[str, str]]) -> str:
    """Render label/value pairs as a markdown bullet list, skipping empty values."""
    return "\n".join(f"- **{label}:** {value}" for label, value in pairs if value)


def code_block(data: dict) -> str:
    """Render a dict as a markdown fenced JSON block, for fields with no fixed shape."""
    return "```\n" + json.dumps(data, indent=2, default=str) + "\n```"


def bullets_or_raw(pairs: list[tuple[str, str]], detail: dict) -> str:
    """Render bullets, or fall back to a raw JSON block if none of them had values."""
    rendered = bullets(pairs)
    return rendered if rendered else code_block(detail)


def first_present(data: dict, keys: tuple[str, ...]) -> str | None:
    """Return the first non-empty value among the given keys in data."""
    for key in keys:
        if data.get(key):
            return data[key]
    return None


# --- AWS console deep links -------------------------------------------------


def ec2_instance_url(region: str, instance_id: str) -> str:
    """Console deep link to a specific EC2 instance."""
    return (
        f"https://{region}.console.aws.amazon.com/ec2/home"
        f"?region={region}#InstanceDetails:instanceId={instance_id}"
    )


def cloudwatch_alarm_url(region: str, alarm_name: str) -> str:
    """Console deep link to a specific CloudWatch alarm."""
    return (
        f"https://{region}.console.aws.amazon.com/cloudwatch/home"
        f"?region={region}#alarmsV2:alarm/{quote(alarm_name)}"
    )


def ecs_task_url(region: str, cluster: str, task_id: str) -> str:
    """Console deep link to a specific ECS task."""
    return (
        f"https://{region}.console.aws.amazon.com/ecs/v2/clusters/{cluster}"
        f"/tasks/{task_id}?region={region}"
    )


def lambda_url(region: str, function_name: str) -> str:
    """Console deep link to a specific Lambda function."""
    return (
        f"https://{region}.console.aws.amazon.com/lambda/home"
        f"?region={region}#/functions/{function_name}"
    )


def acm_url(region: str) -> str:
    """Console deep link to the ACM certificate list."""
    return f"https://{region}.console.aws.amazon.com/acm/home?region={region}#/certificates/list"


def budgets_url() -> str:
    """Console deep link to Budgets (global service)."""
    return "https://console.aws.amazon.com/billing/home#/budgets"


def health_url() -> str:
    """Console deep link to the AWS Health dashboard (global service)."""
    return "https://health.aws.amazon.com/health/home#/account/dashboard/open-issues"


# --- Native CloudWatch Alarm SNS messages -----------------------------------


def alarm_severity(state: str) -> tuple[str, int]:
    """Map a CloudWatch alarm state to a title icon and ntfy priority."""
    if state == "ALARM":
        return "🚨", PRIORITY_URGENT
    if state == "OK":
        return "✅", PRIORITY_LOW
    return "❓", PRIORITY_DEFAULT


def trigger_summary(trigger: dict) -> str:
    """Render a CloudWatch alarm's metric trigger as a short human-readable clause."""
    if not trigger:
        return ""
    metric = trigger.get("MetricName", "?")
    namespace = trigger.get("Namespace", "?")
    operator = trigger.get("ComparisonOperator", "?")
    threshold = trigger.get("Threshold", "?")
    return f"{namespace}/{metric} {operator} {threshold}"


def format_raw_alarm(data: dict) -> Notification:
    """Format a native CloudWatch Alarm SNS message (published directly, not via EventBridge)."""
    name = data.get("AlarmName", "unknown alarm")
    new_state = data.get("NewStateValue", "UNKNOWN")
    old_state = data.get("OldStateValue", "UNKNOWN")
    region = data.get("Region") or "eu-west-1"
    icon, priority = alarm_severity(new_state)

    message = bullets(
        [
            ("Alarm", name),
            ("State", f"{old_state} -> {new_state}"),
            ("Reason", data.get("NewStateReason", "")),
            ("Metric", trigger_summary(data.get("Trigger", {}))),
            ("Time", local_time(data.get("StateChangeTime"))),
        ]
    )
    return Notification(
        title=f"{icon} {name}",
        message=message,
        priority=priority,
        tags="rotating_light" if new_state == "ALARM" else "white_check_mark",
        click=cloudwatch_alarm_url(region, name),
    )


def format_cloudwatch_alarm(detail: dict, region: str) -> Notification:
    """Format an EventBridge 'CloudWatch Alarm State Change' event."""
    name = detail.get("alarmName", "unknown alarm")
    state = detail.get("state", {})
    previous = detail.get("previousState", {})
    new_value = state.get("value", "UNKNOWN")
    icon, priority = alarm_severity(new_value)

    message = bullets(
        [
            ("Alarm", name),
            ("State", f"{previous.get('value', '?')} -> {new_value}"),
            ("Reason", state.get("reason", "")),
            ("Time", local_time(state.get("timestamp"))),
        ]
    )
    return Notification(
        title=f"{icon} {name}",
        message=message,
        priority=priority,
        tags="rotating_light" if new_value == "ALARM" else "white_check_mark",
        click=cloudwatch_alarm_url(region, name),
    )


# --- Infrastructure events ---------------------------------------------------

EC2_STATE_SEVERITY = {
    "terminated": (PRIORITY_HIGH, "🗑️"),
    "terminating": (PRIORITY_DEFAULT, "🗑️"),
    "stopped": (PRIORITY_DEFAULT, "⏹️"),
    "stopping": (PRIORITY_LOW, "⏹️"),
}


def format_ec2_state(detail: dict, region: str) -> Notification:
    """Format an 'EC2 Instance State-change Notification' event."""
    instance_id = detail.get("instance-id", "unknown")
    state = detail.get("state", "unknown")
    priority, icon = EC2_STATE_SEVERITY.get(state, (PRIORITY_DEFAULT, "🖥️"))

    message = bullets(
        [("Instance", f"`{instance_id}`"), ("State", state), ("Region", region)]
    )
    return Notification(
        title=f"{icon} EC2 instance {state}",
        message=message,
        priority=priority,
        tags="computer",
        click=ec2_instance_url(region, instance_id),
    )


def format_ebs(detail: dict, region: str) -> Notification:
    """Format an 'EBS Volume Notification' event."""
    action = detail.get("event", "volume event")
    message = bullets(
        [
            ("Event", action),
            ("Result", detail.get("result", "")),
            ("Cause", detail.get("cause", "")),
            ("Region", region),
        ]
    )
    return Notification(
        title=f"💾 EBS: {action}",
        message=message,
        priority=PRIORITY_LOW,
        tags="floppy_disk",
    )


def ecs_containers(containers: list[dict]) -> str:
    """Summarize ECS container exit codes on one line, non-zero exits called out."""
    parts = []
    for container in containers:
        name = container.get("name", "?")
        code = container.get("exitCode")
        parts.append(f"{name} (exit {code})" if code not in (0, None) else name)
    return ", ".join(parts)


def format_ecs(detail: dict, region: str) -> Notification:
    """Format an 'ECS Task State Change' event."""
    cluster = detail.get("clusterArn", "").rsplit("/", maxsplit=1)[-1]
    task_id = detail.get("taskArn", "").rsplit("/", maxsplit=1)[-1]
    status = detail.get("lastStatus", "unknown")
    containers = detail.get("containers", [])
    failed = any(c.get("exitCode") not in (0, None) for c in containers)

    message = bullets(
        [
            ("Cluster", cluster),
            ("Task", f"`{task_id[:12]}`" if task_id else ""),
            ("Status", status),
            ("Stopped reason", detail.get("stoppedReason", "")),
            ("Containers", ecs_containers(containers)),
        ]
    )
    priority = PRIORITY_HIGH if failed else PRIORITY_DEFAULT
    icon = "❌" if failed else "📦"
    click = ecs_task_url(region, cluster, task_id) if cluster and task_id else None
    return Notification(
        title=f"{icon} ECS task {status.lower()}",
        message=message,
        priority=priority,
        tags="package",
        click=click,
    )


def format_autoscaling(detail: dict, region: str) -> Notification:
    """Format an EC2 Auto Scaling launch/terminate failure event."""
    asg = detail.get("AutoScalingGroupName", "unknown ASG")
    message = bullets(
        [
            ("Auto Scaling group", asg),
            ("Status", detail.get("StatusCode", "")),
            ("Cause", detail.get("Cause", "")),
            ("Region", region),
        ]
    )
    return Notification(
        title=f"⚠️ Auto Scaling failure: {asg}",
        message=message,
        priority=PRIORITY_HIGH,
        tags="warning",
    )


def format_acm(detail: dict, region: str) -> Notification:
    """Format an 'ACM Certificate Approaching Expiration' event."""
    domain = detail.get("CommonName", "unknown domain")
    days = detail.get("DaysToExpiry")
    priority = (
        PRIORITY_HIGH if isinstance(days, int) and days <= 7 else PRIORITY_DEFAULT
    )

    message = bullets(
        [
            ("Domain", domain),
            ("Days to expiry", str(days) if days is not None else "unknown"),
        ]
    )
    return Notification(
        title="🔒 Certificate expiring soon",
        message=message,
        priority=priority,
        tags="lock",
        click=acm_url(region),
    )


def format_lambda_update(detail: dict, region: str) -> Notification:
    """Format a 'Lambda Function Update' deployment event."""
    name = first_present(detail, ("functionName", "FunctionName"))
    message = bullets_or_raw(
        [("Function", name or ""), ("Runtime", detail.get("runtime", ""))], detail
    )
    title_name = name or "unknown function"
    return Notification(
        title=f"🚀 Lambda updated: {title_name}",
        message=message,
        priority=PRIORITY_LOW,
        tags="rocket",
        click=lambda_url(region, title_name),
    )


def format_budget(detail: dict, _region: str) -> Notification:
    """Format a 'Budget Alert' event."""
    name = first_present(detail, ("budgetName", "BudgetName"))
    threshold = first_present(detail, ("threshold", "Threshold"))
    spend = first_present(detail, ("actualSpend", "ActualSpend"))
    message = bullets_or_raw(
        [
            ("Budget", name or ""),
            ("Threshold", threshold or ""),
            ("Actual spend", spend or ""),
        ],
        detail,
    )
    title_name = name or "AWS budget"
    return Notification(
        title=f"💰 Budget alert: {title_name}",
        message=message,
        priority=PRIORITY_HIGH,
        tags="moneybag",
        click=budgets_url(),
    )


def format_health(detail: dict, _region: str) -> Notification:
    """Format an 'AWS Health Event' notification."""
    category = detail.get("eventTypeCategory", "")
    descriptions = detail.get("eventDescription", [])
    text = descriptions[0].get("latestDescription", "") if descriptions else ""
    priority = PRIORITY_URGENT if category == "issue" else PRIORITY_DEFAULT

    message = bullets(
        [
            ("Service", detail.get("service", "")),
            ("Category", category),
            ("Status", detail.get("statusCode", "")),
            ("Details", text),
        ]
    )
    return Notification(
        title=f"🩺 AWS Health: {detail.get('eventTypeCode', 'event')}",
        message=message,
        priority=priority,
        tags="health_worker" if category == "issue" else "information_source",
        click=health_url(),
    )


# --- CloudTrail-sourced security events -------------------------------------


def cloudtrail_actor(identity: dict) -> str:
    """Extract a human-readable actor label from a CloudTrail userIdentity block."""
    return (
        identity.get("arn")
        or identity.get("userName")
        or identity.get("type", "unknown")
    )


def port_range(perm: dict) -> str:
    """Render a security-group permission's port range as 'from-to' or 'all'."""
    from_port = perm.get("fromPort")
    to_port = perm.get("toPort")
    if from_port is None:
        return "all"
    return str(from_port) if from_port == to_port else f"{from_port}-{to_port}"


def describe_sg_rules(params: dict) -> list[str]:
    """Render CloudTrail security-group requestParameters as short rule strings."""
    rules = []
    for perm in params.get("ipPermissions", {}).get("items", []):
        proto = perm.get("ipProtocol", "?")
        ports = port_range(perm)
        for ip_range in perm.get("ipRanges", {}).get("items", []):
            rules.append(f"{proto}/{ports} <- {ip_range.get('cidrIp', '?')}")
    return rules or ["details unavailable"]


def cloudtrail_root_login(detail: dict) -> tuple[str, list[tuple[str, str]], int, str]:
    """Describe an AWS Console root sign-in."""
    mfa = detail.get("additionalEventData", {}).get("MFAUsed", "Unknown")
    result = detail.get("responseElements", {}).get("ConsoleLogin", "Unknown")
    extra = [("Result", result), ("MFA used", mfa)]
    return "🔑 Root console sign-in", extra, PRIORITY_URGENT, "rotating_light"


def cloudtrail_iam_change(detail: dict) -> tuple[str, list[tuple[str, str]], int, str]:
    """Describe an IAM role/policy/user create-delete-attach-detach call."""
    params = detail.get("requestParameters", {})
    target = first_present(params, ("roleName", "userName", "policyName", "policyArn"))
    extra = [("Event", detail.get("eventName", "")), ("Target", target or "unknown")]
    return "🔐 IAM change", extra, PRIORITY_HIGH, "closed_lock_with_key"


def cloudtrail_sg_change(detail: dict) -> tuple[str, list[tuple[str, str]], int, str]:
    """Describe a security-group ingress/egress rule change, flagging world-open rules."""
    params = detail.get("requestParameters", {})
    rules = describe_sg_rules(params)
    world_open = any("0.0.0.0/0" in rule for rule in rules)
    extra = [
        ("Event", detail.get("eventName", "")),
        ("Group", params.get("groupId", "unknown")),
        ("Rules", "; ".join(rules)),
    ]
    if world_open:
        return (
            "🌐 Security group opened to the world",
            extra,
            PRIORITY_URGENT,
            "warning",
        )
    return "🔓 Security group change", extra, PRIORITY_HIGH, "warning"


def cloudtrail_role_assumption(
    detail: dict,
) -> tuple[str, list[tuple[str, str]], int, str]:
    """Describe an STS AssumeRole* call."""
    role_arn = detail.get("requestParameters", {}).get("roleArn", "unknown")
    extra = [("Role", role_arn)]
    return "🎭 Role assumed", extra, PRIORITY_LOW, "detective"


def cloudtrail_s3_policy_change(
    detail: dict,
) -> tuple[str, list[tuple[str, str]], int, str]:
    """Describe an S3 bucket policy or ACL change."""
    bucket = detail.get("requestParameters", {}).get("bucketName", "unknown")
    extra = [("Event", detail.get("eventName", "")), ("Bucket", bucket)]
    return "🪣 S3 bucket policy change", extra, PRIORITY_HIGH, "closed_lock_with_key"


def cloudtrail_generic(detail: dict) -> tuple[str, list[tuple[str, str]], int, str]:
    """Fallback description for a CloudTrail API call with no dedicated formatter."""
    extra = [("Event", detail.get("eventName", "unknown"))]
    return "📋 AWS API call", extra, PRIORITY_DEFAULT, "clipboard"


def _iam_event_names() -> tuple[str, ...]:
    return (
        "CreateRole",
        "DeleteRole",
        "CreatePolicy",
        "DeletePolicy",
        "CreateUser",
        "DeleteUser",
        "AttachRolePolicy",
        "DetachRolePolicy",
    )


def _sg_event_names() -> tuple[str, ...]:
    return (
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress",
    )


CLOUDTRAIL_HANDLERS = {
    "ConsoleLogin": cloudtrail_root_login,
    **{name: cloudtrail_iam_change for name in _iam_event_names()},
    **{name: cloudtrail_sg_change for name in _sg_event_names()},
    "AssumeRole": cloudtrail_role_assumption,
    "AssumeRoleWithSAML": cloudtrail_role_assumption,
    "AssumeRoleWithWebIdentity": cloudtrail_role_assumption,
    "PutBucketPolicy": cloudtrail_s3_policy_change,
    "DeleteBucketPolicy": cloudtrail_s3_policy_change,
    "PutBucketAcl": cloudtrail_s3_policy_change,
}


def format_cloudtrail(detail: dict, region: str) -> Notification:
    """Format a CloudTrail-sourced security event (console sign-in or API call)."""
    event_name = detail.get("eventName", "unknown event")
    actor = cloudtrail_actor(detail.get("userIdentity", {}))
    source_ip = detail.get("sourceIPAddress", "unknown")
    failed = bool(detail.get("errorCode"))

    handler = CLOUDTRAIL_HANDLERS.get(event_name, cloudtrail_generic)
    title, extra_fields, priority, tags = handler(detail)
    if failed:
        title = f"{title} (denied)"
        priority = min(priority + 1, PRIORITY_URGENT)
        tags = "no_entry"

    common_fields = [("Actor", actor), ("Source IP", source_ip), ("Region", region)]
    message = bullets(common_fields + extra_fields)
    return Notification(title=title, message=message, priority=priority, tags=tags)


# --- Dispatch ----------------------------------------------------------------


REGISTRY = {
    ("aws.health", "AWS Health Event"): format_health,
    ("aws.budgets", "Budget Alert"): format_budget,
    ("aws.cloudwatch", "CloudWatch Alarm State Change"): format_cloudwatch_alarm,
    ("aws.acm", "ACM Certificate Approaching Expiration"): format_acm,
    ("aws.lambda", "Lambda Function Update"): format_lambda_update,
    ("aws.ec2", "EC2 Instance State-change Notification"): format_ec2_state,
    ("aws.ecs", "ECS Task State Change"): format_ecs,
    (
        "aws.autoscaling",
        "EC2 Instance Launch/Terminate Unsuccessful",
    ): format_autoscaling,
    ("aws.ec2", "EBS Volume Notification"): format_ebs,
}


def format_unknown(
    source: str, detail_type: str, detail: dict, time_raw: str | None
) -> Notification:
    """Fallback for event types without a dedicated formatter."""
    message = bullets([("Source", source or "unknown"), ("Time", local_time(time_raw))])
    if detail:
        message = f"{message}\n\n{code_block(detail)}"
    return Notification(
        title=f"ℹ️ {detail_type}",
        message=message,
        priority=PRIORITY_DEFAULT,
        tags="grey_question",
    )


def build_notification(event_data: dict) -> Notification:
    """Turn a decoded SNS message body into a formatted Notification."""
    if "AlarmName" in event_data:
        return format_raw_alarm(event_data)

    source = event_data.get("source", "")
    detail_type = event_data.get("detail-type", "Unknown Event")
    detail = event_data.get("detail", {})
    region = event_data.get("region", "eu-west-1")

    if detail_type in CLOUDTRAIL_DETAIL_TYPES:
        return format_cloudtrail(detail, region)

    formatter = REGISTRY.get((source, detail_type))
    if formatter:
        return formatter(detail, region)
    return format_unknown(source, detail_type, detail, event_data.get("time"))


# --- SSM + ntfy delivery -----------------------------------------------------


def get_ntfy_token() -> str:
    """Get ntfy token from Parameter Store, cached for container reuse."""
    global SSM, NTFY_TOKEN  # pylint: disable=global-statement
    if SSM is None:
        SSM = boto3.client("ssm")
    if NTFY_TOKEN is None:
        parameter_name = os.environ.get("NTFY_TOKEN_PARAMETER", "/alerting/ntfy-token")
        response = SSM.get_parameter(Name=parameter_name, WithDecryption=True)
        NTFY_TOKEN = response["Parameter"]["Value"]
    return NTFY_TOKEN


def send_to_ntfy(http: urllib3.PoolManager, notification: Notification) -> None:
    """POST a formatted notification to the configured ntfy endpoint."""
    ntfy_url = os.environ.get("NTFY_URL", "https://ntfy.sh/alerts")
    headers = {
        "Authorization": f"Bearer {get_ntfy_token()}",
        "Title": notification.title,
        "Priority": str(notification.priority),
        "Tags": notification.tags,
        "Markdown": "yes",
    }
    if notification.click:
        headers["Click"] = notification.click

    response = http.request(
        "POST", ntfy_url, body=notification.message.encode("utf-8"), headers=headers
    )
    logger.info(
        "ntfy response: %s - %s", response.status, response.data.decode("utf-8")
    )
    if response.status != 200:
        raise RuntimeError(f"Failed to send notification: {response.status}")


def lambda_handler(event, _context):
    """Handle incoming SNS events and forward them to ntfy as readable notifications."""
    http = urllib3.PoolManager()

    for record in event["Records"]:
        try:
            event_data = json.loads(record["Sns"]["Message"])
            notification = build_notification(event_data)
            send_to_ntfy(http, notification)
            logger.info("Notification sent: %s", notification.title)
        except Exception as exc:
            logger.error("Error processing alert: %s", exc)
            raise

    return {"statusCode": 200, "body": json.dumps("Alerts processed successfully")}

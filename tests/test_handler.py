"""Tests for the alerting handler: formatting, dispatch, and delivery."""

import json
import os
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from aws_ntfy_alerts import handler
from aws_ntfy_alerts.handler import (
    PRIORITY_DEFAULT,
    PRIORITY_HIGH,
    PRIORITY_LOW,
    PRIORITY_URGENT,
    Notification,
    build_notification,
    lambda_handler,
)


def eventbridge_event(source, detail_type, detail=None, **extra):
    """Build a decoded EventBridge-enveloped event dict."""
    event = {
        "source": source,
        "detail-type": detail_type,
        "detail": detail or {},
        "region": "eu-west-1",
        "time": "2025-11-26T21:30:00Z",
    }
    event.update(extra)
    return event


# --- Native CloudWatch Alarm SNS messages -----------------------------------


def test_raw_alarm_state_alarm_is_urgent():
    """A native CloudWatch Alarm entering ALARM is urgent with a click-through link."""
    notification = build_notification(
        {
            "AlarmName": "HighCPU",
            "NewStateValue": "ALARM",
            "OldStateValue": "OK",
            "NewStateReason": "Threshold crossed",
            "Region": "eu-west-1",
            "StateChangeTime": "2025-11-26T21:30:00.000+0000",
            "Trigger": {
                "MetricName": "CPUUtilization",
                "Namespace": "AWS/EC2",
                "ComparisonOperator": "GreaterThanThreshold",
                "Threshold": 80,
            },
        }
    )
    assert notification.priority == PRIORITY_URGENT
    assert "HighCPU" in notification.title
    assert "OK -> ALARM" in notification.message
    assert "AWS/EC2/CPUUtilization" in notification.message
    assert notification.click == (
        "https://eu-west-1.console.aws.amazon.com/cloudwatch/home"
        "?region=eu-west-1#alarmsV2:alarm/HighCPU"
    )


def test_raw_alarm_state_ok_is_low_priority():
    """A native CloudWatch Alarm recovering to OK is low priority."""
    notification = build_notification({"AlarmName": "HighCPU", "NewStateValue": "OK"})
    assert notification.priority == PRIORITY_LOW
    assert notification.tags == "white_check_mark"


def test_raw_alarm_unknown_state_defaults():
    """An unrecognized alarm state falls back to default priority."""
    notification = build_notification(
        {"AlarmName": "Weird", "NewStateValue": "WHATEVER"}
    )
    assert notification.priority == PRIORITY_DEFAULT


def test_eventbridge_cloudwatch_alarm():
    """An EventBridge-wrapped alarm event is formatted like its native counterpart."""
    detail = {
        "alarmName": "DiskFull",
        "state": {
            "value": "ALARM",
            "reason": "over threshold",
            "timestamp": "2025-11-26T21:30:00Z",
        },
        "previousState": {"value": "OK"},
    }
    notification = build_notification(
        eventbridge_event("aws.cloudwatch", "CloudWatch Alarm State Change", detail)
    )
    assert notification.priority == PRIORITY_URGENT
    assert "OK -> ALARM" in notification.message
    assert "DiskFull" in notification.click


# --- Infrastructure events ---------------------------------------------------


@pytest.mark.parametrize(
    "state,expected_priority",
    [
        ("terminated", PRIORITY_HIGH),
        ("stopped", PRIORITY_DEFAULT),
        ("stopping", PRIORITY_LOW),
    ],
)
def test_ec2_state_change_severity(state, expected_priority):
    """EC2 state-change priority reflects how destructive the transition is."""
    detail = {"instance-id": "i-1234567890abcdef0", "state": state}
    notification = build_notification(
        eventbridge_event("aws.ec2", "EC2 Instance State-change Notification", detail)
    )
    assert notification.priority == expected_priority
    assert "i-1234567890abcdef0" in notification.message
    assert "i-1234567890abcdef0" in notification.click


def test_ebs_volume_notification():
    """EBS volume attach/detach events are low priority."""
    detail = {"event": "attachVolume", "result": "available", "cause": ""}
    notification = build_notification(
        eventbridge_event("aws.ec2", "EBS Volume Notification", detail)
    )
    assert notification.priority == PRIORITY_LOW
    assert "attachVolume" in notification.title


def test_ecs_task_state_change_success():
    """A normal ECS task transition links straight to the task in the console."""
    detail = {
        "clusterArn": "arn:aws:ecs:eu-west-1:1234:cluster/my-cluster",
        "taskArn": "arn:aws:ecs:eu-west-1:1234:task/my-cluster/abc123def456",
        "lastStatus": "RUNNING",
        "containers": [{"name": "app", "exitCode": 0}],
    }
    notification = build_notification(
        eventbridge_event("aws.ecs", "ECS Task State Change", detail)
    )
    assert notification.priority == PRIORITY_DEFAULT
    assert "my-cluster" in notification.click
    assert "abc123def456"[:12] in notification.click


def test_ecs_task_state_change_failure():
    """A container exiting non-zero is called out and bumps priority."""
    detail = {
        "clusterArn": "arn:aws:ecs:eu-west-1:1234:cluster/my-cluster",
        "taskArn": "arn:aws:ecs:eu-west-1:1234:task/my-cluster/abc123",
        "lastStatus": "STOPPED",
        "stoppedReason": "Essential container exited",
        "containers": [{"name": "app", "exitCode": 137}],
    }
    notification = build_notification(
        eventbridge_event("aws.ecs", "ECS Task State Change", detail)
    )
    assert notification.priority == PRIORITY_HIGH
    assert "exit 137" in notification.message
    assert "Essential container exited" in notification.message


def test_ecs_task_state_change_without_containers_has_no_click():
    """Without a resolvable cluster/task, no console link is built."""
    detail = {"lastStatus": "PROVISIONING"}
    notification = build_notification(
        eventbridge_event("aws.ecs", "ECS Task State Change", detail)
    )
    assert notification.click is None


def test_autoscaling_failure():
    """An Auto Scaling launch/terminate failure is high priority."""
    detail = {
        "AutoScalingGroupName": "web-asg",
        "StatusCode": "Failed",
        "Cause": "Insufficient capacity",
    }
    notification = build_notification(
        eventbridge_event(
            "aws.autoscaling", "EC2 Instance Launch/Terminate Unsuccessful", detail
        )
    )
    assert notification.priority == PRIORITY_HIGH
    assert "web-asg" in notification.title


@pytest.mark.parametrize(
    "days,expected_priority", [(3, PRIORITY_HIGH), (30, PRIORITY_DEFAULT)]
)
def test_acm_expiration_severity(days, expected_priority):
    """Certificates expiring within a week are bumped to high priority."""
    detail = {"CommonName": "example.com", "DaysToExpiry": days}
    notification = build_notification(
        eventbridge_event("aws.acm", "ACM Certificate Approaching Expiration", detail)
    )
    assert notification.priority == expected_priority
    assert "example.com" in notification.message


def test_lambda_update_with_known_fields():
    """Known deployment fields are rendered as bullets."""
    detail = {"functionName": "my-func", "runtime": "python3.12"}
    notification = build_notification(
        eventbridge_event("aws.lambda", "Lambda Function Update", detail)
    )
    assert "my-func" in notification.title
    assert "python3.12" in notification.message


def test_lambda_update_falls_back_to_raw_json():
    """Unrecognized deployment fields fall back to a raw JSON block."""
    detail = {"weirdField": "unexpected"}
    notification = build_notification(
        eventbridge_event("aws.lambda", "Lambda Function Update", detail)
    )
    assert "```" in notification.message
    assert "weirdField" in notification.message


def test_budget_alert_with_known_fields():
    """Known budget fields are rendered as bullets."""
    detail = {"budgetName": "monthly-spend", "threshold": 80, "actualSpend": "120 USD"}
    notification = build_notification(
        eventbridge_event("aws.budgets", "Budget Alert", detail)
    )
    assert notification.priority == PRIORITY_HIGH
    assert "monthly-spend" in notification.message


def test_budget_alert_falls_back_to_raw_json():
    """An empty budget detail falls back to a raw JSON block."""
    detail = {}
    notification = build_notification(
        eventbridge_event("aws.budgets", "Budget Alert", detail)
    )
    assert "```" in notification.message


def test_health_event_issue_is_urgent():
    """An active AWS Health issue is urgent."""
    detail = {
        "service": "EC2",
        "eventTypeCategory": "issue",
        "eventTypeCode": "AWS_EC2_INSTANCE_RETIREMENT",
        "statusCode": "open",
        "eventDescription": [{"latestDescription": "Instance retirement scheduled"}],
    }
    notification = build_notification(
        eventbridge_event("aws.health", "AWS Health Event", detail)
    )
    assert notification.priority == PRIORITY_URGENT
    assert "Instance retirement scheduled" in notification.message


def test_health_event_scheduled_change_is_default_priority():
    """A scheduled change notice is default priority, not urgent."""
    detail = {"eventTypeCategory": "scheduledChange", "eventTypeCode": "X"}
    notification = build_notification(
        eventbridge_event("aws.health", "AWS Health Event", detail)
    )
    assert notification.priority == PRIORITY_DEFAULT


# --- CloudTrail-sourced security events -------------------------------------


def test_root_console_login():
    """A root console sign-in is always urgent and reports MFA usage."""
    detail = {
        "eventName": "ConsoleLogin",
        "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
        "sourceIPAddress": "1.2.3.4",
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "No"},
    }
    notification = build_notification(
        eventbridge_event("aws.signin", "AWS Console Sign In via CloudTrail", detail)
    )
    assert notification.priority == PRIORITY_URGENT
    assert "Root console sign-in" in notification.title
    assert "MFA used:** No" in notification.message


def test_iam_change():
    """An IAM role/policy/user change reports the target at high priority."""
    detail = {
        "eventName": "CreateRole",
        "userIdentity": {"arn": "arn:aws:iam::123456789012:user/admin"},
        "sourceIPAddress": "1.2.3.4",
        "requestParameters": {"roleName": "new-admin-role"},
    }
    notification = build_notification(
        eventbridge_event("aws.iam", "AWS API Call via CloudTrail", detail)
    )
    assert notification.priority == PRIORITY_HIGH
    assert "new-admin-role" in notification.message


def test_security_group_world_open_is_urgent():
    """A security-group rule opened to 0.0.0.0/0 is urgent and flagged."""
    detail = {
        "eventName": "AuthorizeSecurityGroupIngress",
        "userIdentity": {"arn": "arn:aws:iam::123456789012:user/admin"},
        "sourceIPAddress": "1.2.3.4",
        "requestParameters": {
            "groupId": "sg-123",
            "ipPermissions": {
                "items": [
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "toPort": 22,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                    }
                ]
            },
        },
    }
    notification = build_notification(
        eventbridge_event("aws.ec2", "AWS API Call via CloudTrail", detail)
    )
    assert notification.priority == PRIORITY_URGENT
    assert "opened to the world" in notification.title
    assert "tcp/22 <- 0.0.0.0/0" in notification.message


def test_security_group_change_without_world_open():
    """A restricted security-group change is high priority, not urgent."""
    detail = {
        "eventName": "RevokeSecurityGroupEgress",
        "userIdentity": {"arn": "arn:aws:iam::123456789012:user/admin"},
        "sourceIPAddress": "1.2.3.4",
        "requestParameters": {
            "groupId": "sg-123",
            "ipPermissions": {
                "items": [
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 443,
                        "toPort": 443,
                        "ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]},
                    }
                ]
            },
        },
    }
    notification = build_notification(
        eventbridge_event("aws.ec2", "AWS API Call via CloudTrail", detail)
    )
    assert notification.priority == PRIORITY_HIGH
    assert "Security group change" in notification.title


def test_security_group_all_ports_rule():
    """A rule with no port range is rendered as 'all'."""
    detail = {
        "eventName": "AuthorizeSecurityGroupIngress",
        "userIdentity": {"type": "IAMUser"},
        "requestParameters": {
            "groupId": "sg-123",
            "ipPermissions": {
                "items": [
                    {
                        "ipProtocol": "-1",
                        "ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]},
                    }
                ]
            },
        },
    }
    notification = build_notification(
        eventbridge_event("aws.ec2", "AWS API Call via CloudTrail", detail)
    )
    assert "-1/all <- 10.0.0.0/8" in notification.message


def test_security_group_change_with_no_rule_details():
    """Missing rule details still produce a readable notification, not a crash."""
    detail = {
        "eventName": "AuthorizeSecurityGroupIngress",
        "userIdentity": {"type": "IAMUser"},
        "requestParameters": {"groupId": "sg-123"},
    }
    notification = build_notification(
        eventbridge_event("aws.ec2", "AWS API Call via CloudTrail", detail)
    )
    assert "details unavailable" in notification.message


def test_role_assumption():
    """Routine role assumptions are low priority."""
    detail = {
        "eventName": "AssumeRole",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/ci"},
        "sourceIPAddress": "1.2.3.4",
        "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/deploy"},
    }
    notification = build_notification(
        eventbridge_event("aws.sts", "AWS API Call via CloudTrail", detail)
    )
    assert notification.priority == PRIORITY_LOW
    assert "deploy" in notification.message


def test_s3_policy_change():
    """S3 bucket policy/ACL changes surface the bucket name at high priority."""
    detail = {
        "eventName": "PutBucketPolicy",
        "userIdentity": {"arn": "arn:aws:iam::123456789012:user/admin"},
        "requestParameters": {"bucketName": "my-bucket"},
    }
    notification = build_notification(
        eventbridge_event("aws.s3", "AWS API Call via CloudTrail", detail)
    )
    assert notification.priority == PRIORITY_HIGH
    assert "my-bucket" in notification.message


def test_cloudtrail_generic_event():
    """CloudTrail events with no dedicated formatter still get a readable summary."""
    detail = {
        "eventName": "SomeOtherApiCall",
        "userIdentity": {"type": "IAMUser"},
    }
    notification = build_notification(
        eventbridge_event("aws.somesvc", "AWS API Call via CloudTrail", detail)
    )
    assert notification.priority == PRIORITY_DEFAULT
    assert "SomeOtherApiCall" in notification.message


def test_cloudtrail_denied_call_bumps_priority_and_marks_title():
    """A denied API call is bumped in priority and marked in the title."""
    detail = {
        "eventName": "AssumeRole",
        "userIdentity": {"type": "IAMUser"},
        "errorCode": "AccessDenied",
        "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/secret"},
    }
    notification = build_notification(
        eventbridge_event("aws.sts", "AWS API Call via CloudTrail", detail)
    )
    assert notification.priority == PRIORITY_DEFAULT
    assert "(denied)" in notification.title
    assert notification.tags == "no_entry"


# --- Fallback -----------------------------------------------------------


def test_unknown_event_falls_back_to_generic_notification():
    """An event type with no formatter still produces a readable notification."""
    detail = {"foo": "bar"}
    notification = build_notification(
        eventbridge_event("aws.newthing", "Some New Event", detail)
    )
    assert "Some New Event" in notification.title
    assert "```" in notification.message
    assert "bar" in notification.message


def test_unknown_event_with_no_detail():
    """The fallback formatter tolerates an entirely missing detail block."""
    notification = build_notification({"source": "aws.x", "detail-type": "Y"})
    assert "aws.x" in notification.message


# --- Delivery / orchestration ------------------------------------------------


@mock_aws
@patch("aws_ntfy_alerts.handler.urllib3.PoolManager")
@patch("aws_ntfy_alerts.handler.SSM")
def test_lambda_handler_success(mock_ssm, mock_pool):
    """Successful processing posts markdown, priority, tags, and click headers to ntfy."""
    mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "test-token-123"}}

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.data.decode.return_value = '{"id":"test123"}'
    mock_pool.return_value.request.return_value = mock_response

    os.environ["NTFY_TOKEN_PARAMETER"] = "/alerting/ntfy-token"
    os.environ["NTFY_URL"] = "https://ntfy.test/aws"
    handler.NTFY_TOKEN = None

    event = {
        "Records": [
            {
                "Sns": {
                    "Message": json.dumps(
                        {
                            "source": "aws.ec2",
                            "detail-type": "EC2 Instance State-change Notification",
                            "detail": {
                                "state": "stopped",
                                "instance-id": "i-1234567890abcdef0",
                            },
                            "region": "eu-west-1",
                            "time": "2025-11-26T21:30:00Z",
                        }
                    )
                }
            }
        ]
    }

    response = lambda_handler(event, {})

    assert response["statusCode"] == 200
    assert "Alerts processed successfully" in response["body"]

    mock_pool.return_value.request.assert_called_once()
    call_args = mock_pool.return_value.request.call_args
    assert call_args[0][0] == "POST"
    assert call_args[0][1] == "https://ntfy.test/aws"
    headers = call_args[1]["headers"]
    assert headers["Authorization"] == "Bearer test-token-123"
    assert headers["Markdown"] == "yes"
    assert headers["Priority"] == "3"
    assert "Click" in headers


@mock_aws
@patch("aws_ntfy_alerts.handler.urllib3.PoolManager")
@patch("aws_ntfy_alerts.handler.SSM")
def test_lambda_handler_http_error(mock_ssm, mock_pool):
    """Non-200 ntfy responses raise so SNS retries."""
    mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "test-token-123"}}

    mock_response = MagicMock()
    mock_response.status = 401
    mock_response.data.decode.return_value = "Unauthorized"
    mock_pool.return_value.request.return_value = mock_response

    os.environ["NTFY_TOKEN_PARAMETER"] = "/alerting/ntfy-token"
    handler.NTFY_TOKEN = None

    event = {
        "Records": [
            {
                "Sns": {
                    "Message": json.dumps(
                        {
                            "source": "aws.lambda",
                            "detail-type": "Lambda Function Update",
                            "detail": {"functionName": "some-func"},
                            "region": "us-east-1",
                            "time": "2025-11-26T21:30:00Z",
                        }
                    )
                }
            }
        ]
    }

    with pytest.raises(RuntimeError, match="Failed to send notification: 401"):
        lambda_handler(event, {})

    mock_pool.return_value.request.assert_called_once()


def test_lambda_handler_invalid_json():
    """Malformed SNS message bodies raise instead of being silently dropped."""
    event = {"Records": [{"Sns": {"Message": "invalid json"}}]}

    with pytest.raises(json.JSONDecodeError):
        lambda_handler(event, {})


def test_lambda_handler_empty_records():
    """An empty Records list is a no-op success."""
    event = {"Records": []}

    response = lambda_handler(event, {})

    assert response["statusCode"] == 200
    assert "Alerts processed successfully" in response["body"]


@mock_aws
@patch("aws_ntfy_alerts.handler.urllib3.PoolManager")
@patch("aws_ntfy_alerts.handler.SSM")
def test_multiple_records(mock_ssm, mock_pool):
    """Each SNS record is formatted and sent independently."""
    mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "test-token-123"}}

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.data.decode.return_value = '{"id":"test123"}'
    mock_pool.return_value.request.return_value = mock_response

    os.environ["NTFY_TOKEN_PARAMETER"] = "/alerting/ntfy-token"
    handler.NTFY_TOKEN = None

    event = {
        "Records": [
            {
                "Sns": {
                    "Message": json.dumps(
                        {
                            "source": "aws.ec2",
                            "detail-type": "EC2 Instance State-change Notification",
                            "detail": {"instance-id": "i-1", "state": "stopped"},
                            "region": "us-east-1",
                            "time": "2025-11-26T21:30:00Z",
                        }
                    )
                }
            },
            {
                "Sns": {
                    "Message": json.dumps(
                        {
                            "AlarmName": "SomeAlarm",
                            "NewStateValue": "ALARM",
                            "Region": "us-west-2",
                        }
                    )
                }
            },
        ]
    }

    response = lambda_handler(event, {})

    assert response["statusCode"] == 200
    assert mock_pool.return_value.request.call_count == 2


def test_get_ntfy_token_is_cached():
    """The SSM parameter is only fetched once per container lifetime."""
    handler.SSM = MagicMock()
    handler.NTFY_TOKEN = None
    handler.SSM.get_parameter.return_value = {"Parameter": {"Value": "cached-token"}}

    first = handler.get_ntfy_token()
    second = handler.get_ntfy_token()

    assert first == "cached-token"
    assert second == "cached-token"
    handler.SSM.get_parameter.assert_called_once()

    handler.SSM = None
    handler.NTFY_TOKEN = None


# --- Rendering helpers --------------------------------------------------


@mock_aws
def test_get_ntfy_token_creates_ssm_client_when_uncached():
    """A cold container creates its own SSM client and fetches the token."""
    handler.SSM = None
    handler.NTFY_TOKEN = None
    os.environ["NTFY_TOKEN_PARAMETER"] = "/alerting/ntfy-token"
    previous_region = os.environ.get("AWS_DEFAULT_REGION")
    os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"

    boto3.client("ssm", region_name="eu-west-1").put_parameter(
        Name="/alerting/ntfy-token", Value="real-token", Type="SecureString"
    )

    token = handler.get_ntfy_token()

    assert token == "real-token"
    handler.SSM = None
    handler.NTFY_TOKEN = None
    if previous_region is None:
        del os.environ["AWS_DEFAULT_REGION"]
    else:
        os.environ["AWS_DEFAULT_REGION"] = previous_region


def test_local_time_missing():
    """A missing timestamp renders as 'unknown time'."""
    assert handler.local_time(None) == "unknown time"


def test_local_time_unparseable_returns_raw():
    """An unparseable timestamp is passed through rather than crashing."""
    assert handler.local_time("not-a-date") == "not-a-date"


def test_local_time_naive_datetime_assumed_utc():
    """A timestamp with no timezone is assumed to be UTC."""
    result = handler.local_time("2025-06-15T12:00:00")
    assert result == "15-06-2025 14:00:00"


def test_bullets_skips_empty_values():
    """Fields with empty or missing values are omitted from the bullet list."""
    result = handler.bullets([("A", "1"), ("B", ""), ("C", None)])
    assert result == "- **A:** 1"


def test_send_to_ntfy_without_click_header():
    """No Click header is sent when the notification has no console link."""
    notification = Notification(title="t", message="m", click=None)
    http = MagicMock()
    mock_response = MagicMock(status=200)
    mock_response.data.decode.return_value = "ok"
    http.request.return_value = mock_response

    handler.SSM = MagicMock()
    handler.NTFY_TOKEN = "tok"

    handler.send_to_ntfy(http, notification)

    headers = http.request.call_args[1]["headers"]
    assert "Click" not in headers

    handler.SSM = None
    handler.NTFY_TOKEN = None

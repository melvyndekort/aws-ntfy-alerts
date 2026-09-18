# AWS Ntfy Alerts

AWS alerting system that processes SNS notifications and forwards them to ntfy.

## Overview

This Lambda-based system receives AWS events from SNS topics, formats them into readable alerts, and sends notifications to your ntfy instance.

## Structure

```
aws-ntfy-alerts/
├── aws_ntfy_alerts/    # Python source code
│   ├── __init__.py
│   └── handler.py      # Lambda handler
├── terraform/          # Infrastructure as Code
│   ├── providers.tf    # Provider and S3 backend
│   ├── lambda.tf       # Lambda function and SNS subscription
│   ├── ssm.tf          # SSM parameter for ntfy token
│   ├── secrets.tf      # KMS secrets decryption
│   ├── variables.tf    # Input variables
│   ├── outputs.tf      # Output values
│   ├── terraform.tfvars # Variable values
│   └── secrets.yaml.encrypted # Encrypted secrets
├── tests/              # Test suite
│   └── test_handler.py # Comprehensive tests with 100% coverage
├── .github/            # GitHub workflows
│   └── workflows/
│       └── pipeline.yml # CI/CD pipeline
├── pyproject.toml      # Python project configuration
├── Makefile           # Build automation
└── .gitignore         # Git ignore patterns
```

## Features

- **SNS Integration**: Subscribes to `aws-notifications` topic
- **Source-Specific Formatting**: Dedicated formatters for CloudWatch alarms, EC2/ECS/Auto
  Scaling events, ACM expiry, Lambda deployments, Budgets, AWS Health, and CloudTrail-driven
  security events (root sign-in, IAM/security-group/S3-policy changes, role assumption),
  each rendered as markdown with only the fields that matter for that event type
- **Severity-Aware Priority**: ntfy priority and tags reflect real severity — e.g. a
  security group opened to `0.0.0.0/0` or a root console sign-in is urgent, a routine role
  assumption is low priority, a recovered alarm is low priority
- **Tap-Through Console Links**: Notifications for EC2, CloudWatch alarms, ECS, Lambda, ACM,
  Budgets, and AWS Health link straight to the relevant AWS console page
- **Dual Alarm Formats**: Understands both EventBridge-wrapped events and native CloudWatch
  Alarm SNS messages (alarms that publish to SNS directly instead of via EventBridge)
- **Graceful Fallback**: Any event type without a dedicated formatter still produces a
  readable notification with a raw JSON block, instead of being dropped or mangled
- **Timezone Conversion**: Automatically converts timestamps to Europe/Amsterdam timezone
- **Automatic Retry**: Lambda fails when ntfy is unreachable or any processing error occurs, triggering SNS automatic retry
- **Secure Secrets**: Uses KMS-encrypted secrets in Parameter Store
- **Cost Optimized**: Token cached per Lambda container
- **Comprehensive Testing**: 100% test coverage with mocked dependencies

## Development

### Prerequisites

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) for dependency management
- AWS CLI configured with `awsume`
- Terraform

### Setup

```bash
# Install dependencies
make install

# Run tests
make test

# Lint code
make lint

# Package Lambda
make package

# Clean build artifacts
make clean
```

### Secrets Management

```bash
# Create/edit secrets.yaml with your ntfy token
echo '{"ntfy_token": "your-token-here"}' > terraform/secrets.yaml

# Encrypt secrets
make encrypt

# Decrypt for deployment (done automatically)
make decrypt
```

### Deployment

```bash
# Deploy infrastructure
make apply

# Update Lambda code only
make deploy
```

The `apply` target will:
1. Decrypt secrets
2. Initialize Terraform with S3 backend
3. Apply infrastructure changes

The `deploy` target will:
1. Package Lambda code
2. Update the existing Lambda function

## Configuration

- **S3 Backend**: State stored in `mdekort-tfstate-075673041815/alerting.tfstate`
- **KMS Encryption**: Uses `alias/generic` with context `target=aws-ntfy-alerts`
- **Environment Variables**:
  - `NTFY_URL`: Notification endpoint (default: from terraform.tfvars)
  - `NTFY_TOKEN_PARAMETER`: SSM parameter path (default: `/alerting/ntfy-token`)
  - `LOG_LEVEL`: Lambda logging level

## Notification Design

Each SNS message is routed to a dedicated formatter based on its `source`/`detail-type`
(EventBridge events) or the presence of `AlarmName` (native CloudWatch Alarm SNS messages).
A formatter builds a short title, a markdown body with only the fields that matter, an ntfy
priority (1 min – 5 urgent), a tag, and — where the target is unambiguous — a console
deep-link. Anything without a dedicated formatter still produces a readable notification
(source, time, and a raw JSON block of the `detail`) instead of being dropped or mangled.

| Source | Priority | Notes |
|---|---|---|
| CloudWatch Alarm → `ALARM` (native or EventBridge) | 5 urgent | Links to the alarm in the console |
| CloudWatch Alarm → `OK` | 2 low | Recovery, not urgent |
| Root console sign-in | 5 urgent | Reports whether MFA was used |
| Security group rule opened to `0.0.0.0/0` | 5 urgent | Rule flagged explicitly in the body |
| Other security-group / IAM / S3-policy change | 4 high | |
| CloudTrail API call denied (`errorCode` set) | priority + 1 (capped at 5) | Title marked `(denied)` |
| AWS Health issue | 5 urgent | `scheduledChange`/`accountNotification` stay default |
| Budget alert | 4 high | |
| Auto Scaling launch/terminate failure | 4 high | |
| ECS task stopped with a non-zero container exit | 4 high | |
| EC2 instance terminated | 4 high | `stopped` is default, `stopping` is low |
| ACM certificate expiring in ≤7 days | 4 high | Otherwise default |
| STS role assumption | 2 low | Routine unless denied |
| Lambda deployment update, EBS attach/detach | 2 low | |
| Anything unrecognized | 3 default | Raw JSON fallback |

New EventBridge rules or alarms need a matching entry in the `REGISTRY` dict (or the
`CLOUDTRAIL_HANDLERS` dict for CloudTrail-sourced API calls) in `aws_ntfy_alerts/handler.py`
to get dedicated formatting — otherwise they fall through to the generic formatter above.

## Testing

Run the comprehensive test suite:

```bash
make test                           # Run all tests
uv run pytest --cov=aws_ntfy_alerts # With coverage report
```

Test a live deployment (an EC2 state-change event, formatted with a console deep-link):

```bash
aws sns publish --topic-arn "arn:aws:sns:eu-west-1:075673041815:aws-notifications" \
  --message '{
    "source": "aws.ec2",
    "detail-type": "EC2 Instance State-change Notification",
    "region": "eu-west-1",
    "detail": {"instance-id": "i-1234567890abcdef0", "state": "stopped"}
  }'
```

## Architecture

1. **AWS Events** → SNS Topic (`aws-notifications`)
2. **SNS** → Lambda Function (`aws-ntfy-alerts`)
3. **Lambda** → Parameter Store (get ntfy token)
4. **Lambda** → ntfy API (send notification)

The Lambda processes each SNS record, dispatches it to the matching formatter (see
[Notification Design](#notification-design)), and posts the resulting title/body/priority/tags/click
to your ntfy instance with proper authentication.

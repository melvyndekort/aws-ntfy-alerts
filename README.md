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
│   └── test_handler.py # Comprehensive tests with 94% coverage
├── .github/            # GitHub workflows
│   └── workflows/
│       └── pipeline.yml # CI/CD pipeline
├── pyproject.toml      # Python project configuration
├── Makefile           # Build automation
└── .gitignore         # Git ignore patterns
```

## Features

- **SNS Integration**: Subscribes to `aws-notifications` topic
- **Mobile-Optimized Notifications**: Clean title + minimal body format for better mobile readability
- **Timezone Conversion**: Automatically converts timestamps to Europe/Amsterdam timezone
- **Automatic Retry**: Lambda fails when ntfy is unreachable or any processing error occurs, triggering SNS automatic retry
- **Secure Secrets**: Uses KMS-encrypted secrets in Parameter Store
- **Cost Optimized**: Token cached per Lambda container
- **Comprehensive Testing**: 94% test coverage with mocked dependencies

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

- **S3 Backend**: State stored in `mdekort.tfstate/alerting.tfstate`
- **KMS Encryption**: Uses `alias/generic` with context `target=aws-ntfy-alerts`
- **Environment Variables**:
  - `NTFY_URL`: Notification endpoint (default: from terraform.tfvars)
  - `NTFY_TOKEN_PARAMETER`: SSM parameter path (default: `/alerting/ntfy-token`)
  - `LOG_LEVEL`: Lambda logging level

## Testing

Run the comprehensive test suite:

```bash
make test                           # Run all tests
uv run pytest --cov=aws_ntfy_alerts # With coverage report
```

Test a live deployment:

```bash
aws sns publish --topic-arn "arn:aws:sns:eu-west-1:075673041815:aws-notifications" \
  --message '{"source": "aws.ec2", "detail-type": "Test Alert", "region": "eu-west-1"}'
```

## Architecture

1. **AWS Events** → SNS Topic (`aws-notifications`)
2. **SNS** → Lambda Function (`aws-ntfy-alerts`)
3. **Lambda** → Parameter Store (get ntfy token)
4. **Lambda** → ntfy API (send notification)

The Lambda processes each SNS record, extracts event details, formats a readable message, and posts it to your ntfy instance with proper authentication.

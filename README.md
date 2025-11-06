# AWS Ntfy Alerts

AWS alerting system that processes SNS notifications and forwards them to ntfy.

## Overview

This Lambda-based system receives AWS events from SNS topics, formats them into readable alerts, and sends notifications to your ntfy instance.

## Structure

```
aws-ntfy-alerts/
├── src/                # Python source code
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
│   └── test_handler.py # Comprehensive tests with 96% coverage
├── .github/            # GitHub workflows
│   └── workflows/
│       └── pipeline.yml # CI/CD pipeline
├── pyproject.toml      # Python project configuration
├── Makefile           # Build automation
└── .gitignore         # Git ignore patterns
```

## Features

- **SNS Integration**: Subscribes to `aws-notifications` topic
- **ntfy Notifications**: Sends formatted alerts to ntfy.mdekort.nl/aws
- **Secure Secrets**: Uses KMS-encrypted secrets in Parameter Store
- **Cost Optimized**: Token cached per Lambda container
- **Comprehensive Testing**: 96% test coverage with mocked dependencies

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

# Package Lambda
make package
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
# Deploy everything
make deploy
```

This will:
1. Decrypt secrets
2. Package Lambda code
3. Initialize Terraform with S3 backend
4. Apply infrastructure changes

## Configuration

- **S3 Backend**: State stored in `mdekort.tfstate/alerting.tfstate`
- **KMS Encryption**: Uses `alias/generic` with context `target=alerting`
- **Environment Variables**:
  - `NTFY_URL`: Notification endpoint (default: from terraform.tfvars)
  - `NTFY_TOKEN_PARAMETER`: SSM parameter path
  - `LOG_LEVEL`: Lambda logging level

## Testing

Run the comprehensive test suite:

```bash
make test                    # Run all tests
uv run pytest --cov=src     # With coverage report
```

Test a live deployment:

```bash
aws sns publish --topic-arn "arn:aws:sns:eu-west-1:075673041815:aws-notifications" \
  --message '{"source": "aws.ec2", "detail-type": "Test Alert", "region": "eu-west-1"}'
```

## Architecture

1. **AWS Events** → SNS Topic (`aws-notifications`)
2. **SNS** → Lambda Function (`alerting`)
3. **Lambda** → Parameter Store (get ntfy token)
4. **Lambda** → ntfy API (send notification)

The Lambda processes each SNS record, extracts event details, formats a readable message, and posts it to your ntfy instance with proper authentication.

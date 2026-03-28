# aws-ntfy-alerts

> For global standards, way-of-workings, and pre-commit checklist, see `~/.kiro/steering/behavior.md`

## Role

Python developer and AWS engineer.

## What This Does

AWS Lambda that processes SNS notifications and forwards them to ntfy (self-hosted push notification service). Triggered by SNS subscriptions.

## Lambda Deployment Pattern

Terraform creates the Lambda with dummy code and `ignore_changes` on `source_code_hash`. Actual code is deployed via `make deploy` / CI pipeline using `aws lambda update-function-code`.

## Repository Structure

- `aws_ntfy_alerts/` — Lambda handler source
- `tests/` — Test suite (uses moto for AWS mocking)
- `terraform/` — Lambda, IAM, SNS subscription, SSM parameters
- `Makefile` — `install`, `test`, `lint`, `format`, `package`, `deploy`, `init`, `apply`, `decrypt`, `encrypt`

## Terraform Details

- Backend: S3 key `alerting.tfstate` in `mdekort-tfstate-075673041815`
- Providers: AWS `~> 6.19`
- Secrets: KMS context `target=aws-ntfy-alerts`

## Related Repositories

- `~/src/melvyndekort/tf-aws` — AWS account management

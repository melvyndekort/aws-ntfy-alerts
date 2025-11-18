.PHONY := clean decrypt encrypt install test package init validate apply deploy
.DEFAULT_GOAL := test

ifndef AWS_SESSION_TOKEN
  $(error Not logged in, please run 'awsume')
endif

clean:
	@rm -rf \
	terraform/.terraform \
	terraform/.terraform.lock.hcl \
	terraform/lambda.zip \
	terraform/secrets.yaml \
	lambda.zip \
	.pytest_cache \
	*/__pycache__ \
	aws_ntfy_alerts/__pycache__ \
	tests/__pycache__

decrypt:
	@aws kms decrypt \
	--ciphertext-blob $$(cat terraform/secrets.yaml.encrypted) \
	--output text \
	--query Plaintext \
	--encryption-context target=aws-ntfy-alerts | base64 -d > terraform/secrets.yaml

encrypt:
	@aws kms encrypt \
	--key-id alias/generic \
	--plaintext fileb://terraform/secrets.yaml \
	--encryption-context target=aws-ntfy-alerts \
	--output text \
	--query CiphertextBlob > terraform/secrets.yaml.encrypted
	@rm -f terraform/secrets.yaml

install:
	@uv sync --all-extras

test: install
	@uv run pytest

# Linting
lint:
	@uv run pylint aws_ntfy_alerts tests

package:
	@zip -j terraform/lambda.zip aws_ntfy_alerts/handler.py aws_ntfy_alerts/__init__.py

init:
	@terraform -chdir=terraform init

validate: init
	@terraform -chdir=terraform validate

apply: validate package
	@terraform -chdir=terraform apply -input=true -refresh=true

deploy: apply

resource "aws_ssm_parameter" "ntfy_token" {
  name  = "/aws-ntfy-alerts/ntfy-token"
  type  = "SecureString"
  value = local.secrets.ntfy_token

  tags = {
    Environment = var.environment
  }
}

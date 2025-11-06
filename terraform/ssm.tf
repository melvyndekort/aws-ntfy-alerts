resource "aws_ssm_parameter" "ntfy_token" {
  name  = "/alerting/ntfy-token"
  type  = "SecureString"
  value = local.secrets.ntfy_token

  tags = {
    Environment = var.environment
  }
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "log_level" {
  description = "Log level for Lambda function"
  type        = string
  default     = "INFO"
}

variable "ntfy_url" {
  description = "Ntfy endpoint URL"
  type        = string
  default     = "https://ntfy.sh/alerts"
}

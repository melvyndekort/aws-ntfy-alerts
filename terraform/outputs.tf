output "lambda_function_arn" {
  description = "ARN of the alerting Lambda function"
  value       = aws_lambda_function.alerting.arn
}

output "lambda_function_name" {
  description = "Name of the alerting Lambda function"
  value       = aws_lambda_function.alerting.function_name
}

resource "aws_iam_role" "lambda_role" {
  name = "alerting-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_role.name
}

resource "aws_iam_role_policy" "lambda_ssm" {
  name = "alerting-lambda-ssm"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter"
        ]
        Resource = aws_ssm_parameter.ntfy_token.arn
      }
    ]
  })
}

resource "aws_lambda_function" "alerting" {
  filename         = "lambda.zip"
  function_name    = "alerting"
  role            = aws_iam_role.lambda_role.arn
  handler         = "handler.lambda_handler"
  source_code_hash = filebase64sha256("lambda.zip")
  runtime         = "python3.12"
  timeout         = 30

  environment {
    variables = {
      LOG_LEVEL = var.log_level
      NTFY_TOKEN_PARAMETER = aws_ssm_parameter.ntfy_token.name
      NTFY_URL = var.ntfy_url
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic,
    aws_iam_role_policy.lambda_ssm,
  ]
}

resource "aws_sns_topic_subscription" "alerting" {
  topic_arn = data.terraform_remote_state.tf_aws.outputs.notifications_topic_arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.alerting.arn
}

resource "aws_lambda_permission" "allow_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alerting.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = data.terraform_remote_state.tf_aws.outputs.notifications_topic_arn
}

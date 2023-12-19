# --- Retrieve ARNs of secrets needed by lambda function
data "aws_secretsmanager_secret" "this" {
  for_each = toset([
    "packer-revocation/token",
    "packer-revocation/hmac_token",
    "packer-revocation/slack_url"
  ])
  name = each.value
}

# --- Zip code. May need to use source directory once other Python functions are added
data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/scripts/lambda_function.py"
  output_path = "${path.module}/scripts/lambda_function_payload.zip"
}

resource "aws_lambda_function" "this" {
  filename      = data.archive_file.lambda.output_path
  function_name = "packer_revocation_transform"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "lambda_function.lambda_handler"
  layers = [
    "arn:aws:lambda:us-west-2:345057560386:layer:AWS-Parameters-and-Secrets-Lambda-Extension:11"
  ]

  source_code_hash = data.archive_file.lambda.output_base64sha256

  runtime = "python3.11"

  environment {
    variables = {
      PARAMETERS_SECRETS_EXTENSION_LOG_LEVEL = "debug"
      HMAC_TOKEN_ARN = data.aws_secretsmanager_secret.this["packer-revocation/hmac_token"].arn
      GITHUB_TOKEN_ARN = data.aws_secretsmanager_secret.this["packer-revocation/token"].arn
      SLACK_URL = data.aws_secretsmanager_secret.this["packer-revocation/slack_url"].arn
      SECRETS_EXTENSION_HTTP_PORT = 2773
    }
  }
}

# --- Check if this is needed with API Gateway in effect
resource "aws_lambda_function_url" "this" {
  function_name      = aws_lambda_function.this.function_name
  authorization_type = "NONE"
}

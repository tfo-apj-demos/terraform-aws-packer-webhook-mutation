data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

data "aws_secretsmanager_secret" "this" {
  for_each = toset(["packer-revocation/token", "packer-revocation/hmac_token"])
  name = each.value
}

resource "aws_iam_policy" "retrieve_secret" {
  name = "retrieve-secret"
  policy = jsonencode({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": data.aws_secretsmanager_secret.this["packer-revocation/token"].arn
    },
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": data.aws_secretsmanager_secret.this["packer-revocation/hmac_token"].arn
    }
  ]
})
}

resource "aws_iam_role" "iam_for_lambda" {
  name               = "iam_for_lambda"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    aws_iam_policy.retrieve_secret.arn
  ]
}

resource "aws_lambda_permission" "this" {
  function_name = aws_lambda_function.this.function_name
  action = "lambda:InvokeFunctionUrl"
  principal = "*"
  function_url_auth_type = "NONE"
  statement_id = "url"
}

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
      SECRETS_EXTENSION_HTTP_PORT = 2773
    }
  }
}

resource "aws_lambda_function_url" "this" {
  function_name      = aws_lambda_function.this.function_name
  authorization_type = "NONE"
}

output "webhook_url" {
  value = aws_lambda_function_url.this.function_url
}

import {
  id = "t8j4t4inja"
  to = aws_api_gateway_rest_api.this
}
resource "aws_api_gateway_rest_api" "this" {
  name = "HCP Packer"
  endpoint_configuration {
    types = ["EDGE"]
  }
}

# import {
#   id = 
# }
# resource "aws_api_gateway_deployment" "this" {
#   rest_api_id = aws_api_gateway_rest_api.this.id
#   lifecycle {
#     create_before_destroy = true
#   }
# }

import {
  id = "t8j4t4inja/test"
  to = aws_api_gateway_stage
}

resource "aws_api_gateway_stage" "this" {
  deployment_id = aws_api_gateway_deployment.this.id
  rest_api_id   = aws_api_gateway_rest_api.this.id
  stage_name    = "test"
}

resource "aws_api_gateway_resource" "this" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id = aws_api_gateway_rest_api.this.root_resource_id
  path_part = "{proxy+}"
}

resource "aws_api_gateway_method" "this" {
  rest_api_id   = aws_api_gateway_rest_api.this.id
  resource_id   = aws_api_gateway_resource.this.id
  http_method   = "ANY"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "this" {
  rest_api_id             = aws_api_gateway_rest_api.this.id
  resource_id             = aws_api_gateway_resource.this.id
  http_method             = aws_api_gateway_method.this.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.this.invoke_arn
  credentials = "arn:aws:iam::542594126947:role/APIGWInvokeLambda"
}



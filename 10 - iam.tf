# --- Configure role for lambda function to retrieve secrets from AWS SM
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
    },
        {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": data.aws_secretsmanager_secret.this["packer-revocation/slack_url"].arn
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

# --- Configure role for API Gateway to invoke lambda function
data "aws_iam_policy_document" "api_gateway" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_policy" "invoke_lambda" {
  name = "InvokeLambda-PackerFunction"
  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow"
        "Action": "lambda:InvokeFunction",
        "Resource": aws_lambda_function.this.arn
      }
    ]
  })
}

resource "aws_iam_role" "api_gateway" {
  name               = "APIGWInvokeLambda"
  assume_role_policy = data.aws_iam_policy_document.api_gateway.json
  managed_policy_arns = [
    aws_iam_policy.invoke_lambda.arn
  ]

}
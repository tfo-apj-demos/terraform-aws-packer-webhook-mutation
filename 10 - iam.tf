# --- Configure assume role policy for Lambda function
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

# --- IAM role for Lambda function (simplified with AWS managed policy)
resource "aws_iam_role" "iam_for_lambda" {
  name               = "iam_for_lambda"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  
  # Using AWS managed policy for basic Lambda execution (Option 3)
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  ]
}

# --- Lambda permission for function URL (if you're using function URLs)
resource "aws_lambda_permission" "this" {
  function_name          = aws_lambda_function.this.function_name
  action                = "lambda:InvokeFunctionUrl"
  principal             = "*"
  function_url_auth_type = "NONE"
  statement_id          = "url"
}

# --- Configure assume role policy for API Gateway
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

# --- IAM policy for API Gateway to invoke Lambda
resource "aws_iam_policy" "invoke_lambda" {
  name = "InvokeLambda-PackerFunction"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow"
        "Action" : "lambda:InvokeFunction",
        "Resource" : aws_lambda_function.this.arn
      }
    ]
  })
}

# --- IAM role for API Gateway
resource "aws_iam_role" "api_gateway" {
  name               = "APIGWInvokeLambda"
  assume_role_policy = data.aws_iam_policy_document.api_gateway.json
  
  managed_policy_arns = [
    aws_iam_policy.invoke_lambda.arn
  ]
}
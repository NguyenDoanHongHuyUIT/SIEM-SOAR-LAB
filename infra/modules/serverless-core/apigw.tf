resource "aws_apigatewayv2_api" "slack" {
  name          = "${var.name_prefix}-slack"
  protocol_type = "HTTP"
  description   = "Slack interactive components (approval buttons)"
}

resource "aws_apigatewayv2_integration" "slack" {
  api_id                 = aws_apigatewayv2_api.slack.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.fn["slack_interact"].invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 5000
}

resource "aws_apigatewayv2_route" "slack" {
  api_id    = aws_apigatewayv2_api.slack.id
  route_key = "POST /slack/interact"
  target    = "integrations/${aws_apigatewayv2_integration.slack.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.slack.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 10
    throttling_rate_limit  = 5
  }
}

resource "aws_lambda_permission" "apigw_slack" {
  statement_id  = "AllowApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn["slack_interact"].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.slack.execution_arn}/*/*"
}

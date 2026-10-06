resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/vendedlogs/states/${local.sfn_name}"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "sfn_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sfn" {
  name               = "${var.name_prefix}-sfn-role"
  assume_role_policy = data.aws_iam_policy_document.sfn_trust.json
}

data "aws_iam_policy_document" "sfn_perm" {
  statement {
    sid = "LogDelivery"
    actions = [
      "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries", "logs:PutResourcePolicy", "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }
  statement {
    sid     = "InvokeWorkflowLambdas"
    actions = ["lambda:InvokeFunction"]
    resources = [
      for k in ["enrich", "notify", "preflight", "save_state", "contain", "restore", "case_ops"] :
      aws_lambda_function.fn[k].arn
    ]
  }
}

resource "aws_iam_role_policy" "sfn" {
  name   = "invoke-lambdas"
  role   = aws_iam_role.sfn.id
  policy = data.aws_iam_policy_document.sfn_perm.json
}

resource "aws_sfn_state_machine" "case" {
  name     = local.sfn_name
  role_arn = aws_iam_role.sfn.arn
  type     = "STANDARD"

  definition = templatefile("${path.module}/../../../statemachine/case_workflow.asl.json", {
    fn_enrich     = aws_lambda_function.fn["enrich"].arn
    fn_notify     = aws_lambda_function.fn["notify"].arn
    fn_preflight  = aws_lambda_function.fn["preflight"].arn
    fn_save_state = aws_lambda_function.fn["save_state"].arn
    fn_contain    = aws_lambda_function.fn["contain"].arn
    fn_restore    = aws_lambda_function.fn["restore"].arn
    fn_case_ops   = aws_lambda_function.fn["case_ops"].arn
  })

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = false # task payloads can contain resource details; keep them out of logs
    level                  = "ERROR"
  }

  tracing_configuration {
    enabled = true
  }

  tags = { Zone = "security" }
}

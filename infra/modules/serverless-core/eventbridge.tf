resource "aws_sqs_queue" "ingest_dlq" {
  name                      = "${var.name_prefix}-ingest-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

data "aws_iam_policy_document" "dlq" {
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.ingest_dlq.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.ingest_dlq.id
  policy    = data.aws_iam_policy_document.dlq.json
}

# GuardDuty is the ONLY cloud path into cases (paper 5.2: avoids duplicate cases from several ingest paths).
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${var.name_prefix}-guardduty"
  description = "GuardDuty findings >= ${var.min_guardduty_severity} -> case ingest"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail        = { severity = [{ numeric = [">=", var.min_guardduty_severity] }] }
  })
}

# Wazuh/Suricata alerts of rules in the *active* state are pushed by the Wazuh custom integration.
resource "aws_cloudwatch_event_rule" "wazuh" {
  name        = "${var.name_prefix}-wazuh"
  description = "Active Wazuh/Suricata alerts -> case ingest"
  event_pattern = jsonencode({
    source        = ["siemsoar.wazuh"]
    "detail-type" = ["Wazuh Alert"]
  })
}

locals {
  ingest_rules = {
    guardduty = aws_cloudwatch_event_rule.guardduty.name
    wazuh     = aws_cloudwatch_event_rule.wazuh.name
  }
}

resource "aws_cloudwatch_event_target" "ingest" {
  for_each = local.ingest_rules
  rule     = each.value
  arn      = aws_lambda_function.fn["ingest"].arn

  retry_policy {
    maximum_retry_attempts       = 3
    maximum_event_age_in_seconds = 3600
  }
  dead_letter_config {
    arn = aws_sqs_queue.ingest_dlq.arn
  }
}

resource "aws_lambda_permission" "events_ingest" {
  for_each      = local.ingest_rules
  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn["ingest"].function_name
  principal     = "events.amazonaws.com"
  source_arn    = each.key == "guardduty" ? aws_cloudwatch_event_rule.guardduty.arn : aws_cloudwatch_event_rule.wazuh.arn
}

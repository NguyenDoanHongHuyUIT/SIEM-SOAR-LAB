resource "aws_sns_topic" "notify" {
  name = "${var.name_prefix}-notify"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.notify.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# CloudWatch alarms publish here too
data "aws_iam_policy_document" "notify_topic" {
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.notify.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "budgets.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "notify" {
  arn    = aws_sns_topic.notify.arn
  policy = data.aws_iam_policy_document.notify_topic.json
}

resource "aws_sns_topic" "notify" {
  name = "${var.name_prefix}-notify"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.notify.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
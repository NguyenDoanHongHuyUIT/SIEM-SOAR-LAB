# Secrets are created as placeholders. Set the real values out of band so they never reach
# Terraform state:  aws ssm put-parameter --name /siemsoar/slack/bot_token --type SecureString --overwrite --value xoxb-...
locals {
  slack_secure_params = toset(["bot_token", "signing_secret"])
}

resource "aws_ssm_parameter" "slack_secure" {
  for_each = local.slack_secure_params
  name     = "/${var.name_prefix}/slack/${each.key}"
  type     = "SecureString"
  value    = "CHANGE_ME"
  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "slack_approvers" {
  name        = "/${var.name_prefix}/slack/approver_ids"
  type        = "String"
  value       = "CHANGE_ME"
  description = "Comma separated Slack member ids allowed to approve (empty/CHANGE_ME = nobody)."
  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "slack_channel" {
  name  = "/${var.name_prefix}/slack/channel"
  type  = "String"
  value = var.slack_channel == "" ? "CHANGE_ME" : var.slack_channel
  lifecycle {
    ignore_changes = [value]
  }
}

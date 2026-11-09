# The Slack secrets are not Terraform resources: `value` + ignore_changes only hid the diff, every refresh read the
# decrypted value back into state, and the write-only `value_wo` would overwrite the real value on the first apply
# (its version going from unset to 1 is an update). They are set out of band (docs/runbook.md):
#   aws ssm put-parameter --name /siemsoar/slack/bot_token --type SecureString --overwrite --value xoxb-...
# Until they exist Slack is "not configured" and SNS email carries the notices.
removed {
  from = aws_ssm_parameter.slack_secure
  lifecycle {
    destroy = false # keep the parameters on AWS, forget them in state
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

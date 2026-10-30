# Secrets are created as placeholders and the real values are set out of band:
#   aws ssm put-parameter --name /siemsoar/slack/bot_token --type SecureString --overwrite --value xoxb-...
# The placeholder goes through the write-only `value_wo`, so the parameter value is never stored in Terraform state, not
# even after a refresh (`value` + ignore_changes only hid the diff: every refresh read the decrypted real value back into
# state). Terraform writes `value_wo` only when `value_wo_version` changes: keep it at 1, or the next apply overwrites
# the real value with the placeholder.
locals {
  slack_secure_params = toset(["bot_token", "signing_secret"])
}

resource "aws_ssm_parameter" "slack_secure" {
  for_each         = local.slack_secure_params
  name             = "/${var.name_prefix}/slack/${each.key}"
  type             = "SecureString"
  value_wo         = "CHANGE_ME"
  value_wo_version = 1
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

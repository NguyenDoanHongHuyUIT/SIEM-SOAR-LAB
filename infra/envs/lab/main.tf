module "core" {
  source = "../../modules/serverless-core"

  alert_email              = var.alert_email
  slack_channel            = var.slack_channel
  dry_run                  = var.dry_run
  enable_guardduty         = var.enable_guardduty
  enable_security_hub      = var.enable_security_hub
  monthly_budget_usd       = var.monthly_budget_usd
  approval_timeout_seconds = var.approval_timeout_seconds
  restore_timeout_seconds  = var.restore_timeout_seconds
  enable_fault_injection   = var.enable_fault_injection
}

# On-demand plane: Wazuh manager + dashboard + lab EC2 (Wazuh agent, Suricata). Destroyed between sessions.
module "lab" {
  count  = var.lab_enabled ? 1 : 0
  source = "../../modules/lab-ondemand"

  rules_bucket     = module.core.rules_bucket
  rules_bucket_arn = module.core.rules_bucket_arn
  logs_bucket      = module.core.logs_bucket
  logs_bucket_arn  = module.core.logs_bucket_arn
  event_bus_arn    = module.core.default_event_bus_arn
}

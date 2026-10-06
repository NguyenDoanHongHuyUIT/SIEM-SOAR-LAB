module "core" {
  source      = "../../modules/serverless-core"
  alert_email = var.alert_email
}

output "core" {
  value = {
    evidence_bucket   = module.core.evidence_bucket
    cases_table       = module.core.cases_table
    notify_topic_arn  = module.core.notify_topic_arn
    state_machine_arn = module.core.state_machine_arn
  }
}
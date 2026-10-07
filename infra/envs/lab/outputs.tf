output "core" {
  value = {
    evidence_bucket       = module.core.evidence_bucket
    rules_bucket          = module.core.rules_bucket
    logs_bucket           = module.core.logs_bucket
    cases_table           = module.core.cases_table
    notify_topic_arn      = module.core.notify_topic_arn
    state_machine_arn     = module.core.state_machine_arn
    slack_interaction_url = module.core.slack_interaction_url
  }
}

output "lab" {
  value = var.lab_enabled ? {
    manager_instance_id    = module.lab[0].manager_instance_id
    sensor_instance_id     = module.lab[0].sensor_instance_id
    victim_user            = module.lab[0].victim_user
    deploy_rules_document  = module.lab[0].deploy_rules_document
    dashboard_port_forward = module.lab[0].dashboard_port_forward
  } : null
}

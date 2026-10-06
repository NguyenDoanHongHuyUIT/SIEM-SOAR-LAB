output "evidence_bucket" { value = aws_s3_bucket.evidence.bucket }
output "cases_table" { value = aws_dynamodb_table.cases.name }
output "notify_topic_arn" { value = aws_sns_topic.notify.arn }
output "state_machine_arn" { value = aws_sfn_state_machine.case.arn }
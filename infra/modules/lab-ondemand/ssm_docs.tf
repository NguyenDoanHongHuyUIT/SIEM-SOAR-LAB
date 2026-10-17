# Rule deployment is an SSM Run Command document so the GitHub OIDC role never needs network access to hosts.
resource "aws_ssm_document" "deploy_rules" {
  name            = "${var.name_prefix}-deploy-rules"
  document_type   = "Command"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Pull a rule release from S3, validate it, activate it, roll back automatically on failure."
    parameters = {
      Target  = { type = "String", allowedValues = ["manager", "sensor"] }
      Release = { type = "String", description = "git sha or 'current'", allowedPattern = "^([0-9a-f]{7,40}|current)$" }
    }
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "deploy"
      inputs = {
        timeoutSeconds = "600"
        runCommand = [
          "set -euo pipefail",
          "aws s3 sync s3://${var.rules_bucket}/bootstrap/ /opt/siemsoar/bootstrap/ --region ${local.region}",
          "bash /opt/siemsoar/bootstrap/scripts/deploy_rules.sh {{ Target }} {{ Release }}",
        ]
      }
    }]
  })
}

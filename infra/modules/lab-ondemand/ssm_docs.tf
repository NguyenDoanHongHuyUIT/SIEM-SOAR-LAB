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
        # aws:runShellScript runs /bin/sh (dash on Ubuntu): POSIX options only. `set -o pipefail` failed the first
        # real deployment; deploy_rules.sh itself runs under bash with pipefail.
        runCommand = [
          "set -eu",
          "aws s3 sync s3://${var.rules_bucket}/bootstrap/ /opt/siemsoar/bootstrap/ --region ${local.region} --only-show-errors",
          "bash /opt/siemsoar/bootstrap/scripts/deploy_rules.sh {{ Target }} {{ Release }}",
        ]
      }
    }]
  })
}

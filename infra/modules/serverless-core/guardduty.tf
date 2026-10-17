resource "aws_guardduty_detector" "main" {
  count                        = var.enable_guardduty ? 1 : 0
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = { Zone = "security" }
}

resource "aws_securityhub_account" "main" {
  count = var.enable_security_hub ? 1 : 0
}

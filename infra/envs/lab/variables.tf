variable "region" {
  type    = string
  default = "ap-southeast-1"
}

variable "alert_email" {
  type        = string
  description = "SNS fallback + budget alerts"
}

variable "slack_channel" {
  type    = string
  default = ""
}

variable "dry_run" {
  type        = bool
  default     = true
  description = "Start in dry-run: the workflow runs end to end but never mutates EC2/IAM. Flip to false for real containment."
}

variable "lab_enabled" {
  type        = bool
  default     = false
  description = "On-demand plane (Wazuh manager + lab host). Off by default to save credit; the lab-session workflow flips it."
}

variable "enable_guardduty" {
  type    = bool
  default = true
}

variable "enable_security_hub" {
  type    = bool
  default = false
}

variable "monthly_budget_usd" {
  type    = number
  default = 50
}

variable "approval_timeout_seconds" {
  type    = number
  default = 3600
}

variable "restore_timeout_seconds" {
  type    = number
  default = 86400
}

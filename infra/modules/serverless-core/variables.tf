variable "name_prefix" {
  type        = string
  default     = "siemsoar"
  description = "Prefix for every resource name and SSM parameter path."
}

variable "alert_email" {
  type        = string
  description = "Email subscribed to the SNS fallback topic (notifications + ops alarms)."
}

variable "slack_channel" {
  type        = string
  default     = ""
  description = "Slack channel id (C0123...). Empty = read /<prefix>/slack/channel from SSM."
}

variable "approval_timeout_seconds" {
  type        = number
  default     = 3600
  description = "How long a case waits for the containment decision before it EXPIRES."
}

variable "restore_timeout_seconds" {
  type        = number
  default     = 86400
  description = "How long an isolated resource waits for the restore decision before fail-safe."
}

variable "dedup_window_seconds" {
  type    = number
  default = 3600
}

variable "breaker_limit" {
  type        = number
  default     = 3
  description = "Max isolations per breaker window before automation stops and asks a human."
}

variable "breaker_window_seconds" {
  type    = number
  default = 3600
}

variable "stop_risk_threshold" {
  type        = number
  default     = 85
  description = "EC2 instances are also stopped when the case risk score is at least this value."
}

variable "dry_run" {
  type        = bool
  default     = false
  description = "Walk the whole workflow but never mutate EC2/IAM (demo / first deployment)."
}

variable "iam_target_prefix" {
  type        = string
  default     = "lab-"
  description = "SOAR may only disable keys of IAM users whose name starts with this prefix."
}

variable "min_guardduty_severity" {
  type        = number
  default     = 4
  description = "GuardDuty findings below this severity never become cases."
}

variable "enable_guardduty" {
  type        = bool
  default     = true
  description = "Create the GuardDuty detector (set false if the account already has one)."
}

variable "enable_security_hub" {
  type        = bool
  default     = false
  description = "Optional Security Hub aggregation (paper: optional)."
}

variable "monthly_budget_usd" {
  type        = number
  default     = 50
  description = "AWS Budgets alert threshold for the lab account."
}

variable "log_retention_days" {
  type    = number
  default = 14
}

variable "evidence_retention_days" {
  type    = number
  default = 7
}

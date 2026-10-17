variable "name_prefix" {
  type    = string
  default = "siemsoar"
}

variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/24"
}

variable "manager_instance_type" {
  type        = string
  default     = "t3.large"
  description = "Wazuh all-in-one (manager+indexer+dashboard) needs ~8 GiB RAM."
}

variable "sensor_instance_type" {
  type    = string
  default = "t3.small"
}

variable "wazuh_version" {
  type        = string
  default     = "4.14" # manager (wazuh-install.sh) and agent apt pin; keep CI `WAZUH_VERSION` in the same minor
  description = "Wazuh minor version. The manager must be >= the agent, so the agent is pinned to the same minor."
}

variable "rules_bucket" { type = string }
variable "rules_bucket_arn" { type = string }
variable "logs_bucket" { type = string }
variable "logs_bucket_arn" { type = string }
variable "event_bus_arn" { type = string }

variable "iam_target_prefix" {
  type    = string
  default = "lab-"
}

variable "manager_volume_gb" {
  type    = number
  default = 50
}

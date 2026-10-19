variable "name_prefix" {
  type    = string
  default = "siemsoar"
}

variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/24"
}

variable "manager_instance_type" {
  type = string
  # Wazuh quickstart (all-in-one, 1-25 agents) recommends 4 vCPU, 8 GiB, 50 GB:
  # https://documentation.wazuh.com/current/quickstart.html . t3.large (2 vCPU) was below it; measured on the lab it
  # was not overloaded (no OOM, PSI 0, no dropped events, CPU avg 6 %, peaks only at boot). t3a.xlarge (4 vCPU,
  # 16 GiB, x86_64) meets the recommendation at the lowest 4-vCPU list price in us-east-1 (Pricing API, 2026-10-19).
  default     = "t3a.xlarge"
  description = "Wazuh all-in-one (manager + indexer + dashboard); keep at or above the Wazuh recommendation."
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

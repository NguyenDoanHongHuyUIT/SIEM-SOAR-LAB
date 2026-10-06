variable "region" {
  type    = string
  default = "ap-southeast-1"
}

variable "github_repo" {
  type        = string
  description = "dạng user/siem-soar-lab"
}
variable "name_prefix" {
  type    = string
  default = "siemsoar"
}

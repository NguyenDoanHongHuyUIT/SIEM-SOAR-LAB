variable "region" {
  type    = string
  default = "us-east-1" # cheapest on-demand EC2 prices (t3.large+t3.small: 0.104 USD/h vs 0.132 in ap-southeast-1)
}

variable "github_repo" {
  type        = string
  description = "dạng user/siem-soar-lab"
}
variable "name_prefix" {
  type    = string
  default = "siemsoar"
}

variable "github_repo_ids" {
  type        = string
  default     = ""
  description = "owner@<owner_id>/repo@<repo_id> as GitHub puts it in the OIDC sub claim (gh api repos/<owner>/<repo>)"
}

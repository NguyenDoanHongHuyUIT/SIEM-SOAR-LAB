terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket       = "siemsoar-tfstate-<ACCOUNT_ID>"
    key          = "lab/terraform.tfstate"
    region       = "ap-southeast-1"
    use_lockfile = true
  }
}
terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # Partial configuration: the state bucket name contains the account id, so it is injected at init time
  #   terraform init -backend-config=backend.hcl            (local, copy backend.hcl.example)
  #   CI: -backend-config="bucket=$TFSTATE_BUCKET" (see .github/workflows/terraform.yml)
  backend "s3" {
    key          = "lab/terraform.tfstate"
    region       = "ap-southeast-1"
    use_lockfile = true
    encrypt      = true
  }
}

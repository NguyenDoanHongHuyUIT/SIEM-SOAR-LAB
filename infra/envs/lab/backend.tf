terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.69"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # Partial configuration: the state bucket name contains the account id and the region is chosen per deployment, so
  # both are injected at init time (a backend block cannot read variables)
  #   terraform init -backend-config=backend.hcl            (local, copy backend.hcl.example)
  #   CI: -backend-config="bucket=$TFSTATE_BUCKET" -backend-config="region=$AWS_REGION" (.github/workflows/terraform.yml)
  backend "s3" {
    key          = "lab/terraform.tfstate"
    use_lockfile = true
    encrypt      = true
  }
}

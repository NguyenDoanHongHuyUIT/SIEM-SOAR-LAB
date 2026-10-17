provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = "siem-soar-lab"
      ManagedBy = "terraform"
    }
  }
}

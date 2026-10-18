terraform {
  # 1.10+ can lock state with S3 alone (use_lockfile), so no DynamoDB lock table
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.69"
    }
  }
}

# Terraform's record of what it created lives in the tf-state bucket made by
# infrastructure/bootstrap, never in Git (it can hold sensitive details).
#
# The bucket name isn't written here: it's passed at init time, so it isn't
# published in the repository.
#   terraform init -backend-config="bucket=<tf-state bucket name>"
terraform {
  backend "s3" {
    key          = "environments/dev/terraform.tfstate"
    region       = "us-east-2"
    encrypt      = true
    use_lockfile = true # Stops two runs changing the same resources at once
  }
}

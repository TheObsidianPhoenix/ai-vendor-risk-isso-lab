provider "aws" {
  region = var.region

  # Every resource gets these tags, so the ISSO can find and cost everything
  # this project owns (CM-8, system component inventory).
  default_tags {
    tags = {
      Project            = "counterpart"
      Environment        = var.environment
      ManagedBy          = "terraform"
      Repository         = "TheObsidianPhoenix/ai-vendor-risk-isso-lab"
      DataClassification = "synthetic"
    }
  }
}

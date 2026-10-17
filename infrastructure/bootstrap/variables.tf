variable "region" {
  description = "AWS region for the state bucket. Same as the project."
  type        = string
  default     = "us-east-2"
}

variable "github_repository" {
  description = "The only GitHub repository allowed to request AWS credentials, as owner/name."
  type        = string
  default     = "TheObsidianPhoenix/ai-vendor-risk-isso-lab"
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", var.github_repository))
    error_message = "Use owner/repository."
  }
}

variable "region" {
  description = "AWS region. The project account was provisioned in US East (Ohio)."
  type        = string
  default     = "us-east-2"
}

variable "environment" {
  description = "Environment name."
  type        = string
  default     = "dev"
}

variable "alert_email" {
  description = "Where security and budget alerts go. Set in terraform.tfvars (never committed)."
  type        = string
  default     = ""
  sensitive   = true
}

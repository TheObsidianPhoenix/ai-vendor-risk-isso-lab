variable "name" {
  description = "Name prefix for resources, such as counterpart-dev."
  type        = string
}

variable "kms_key_arn" {
  description = "The project's customer managed KMS key (encrypts the alert topic)."
  type        = string
}

variable "alert_email" {
  description = "Where security and budget alerts go. Set in terraform.tfvars, which is never committed."
  type        = string
  default     = ""
  sensitive   = true
}

variable "budget_limit_usd" {
  description = "Monthly budget in US dollars."
  type        = number
  default     = 10
}

variable "budget_alert_thresholds_usd" {
  description = "Send an email when actual monthly spend passes each of these amounts."
  type        = list(number)
  default     = [5, 10]
}

variable "tags" {
  description = "Tags added to every resource."
  type        = map(string)
  default     = {}
}

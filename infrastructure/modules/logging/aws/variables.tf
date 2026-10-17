variable "name" {
  description = "Name prefix for resources, such as counterpart-dev."
  type        = string
}

variable "kms_key_arn" {
  description = "The project's customer managed KMS key."
  type        = string
}

variable "object_lock_days" {
  description = "Object Lock retention for audit records (decision D-05: 30 days in the lab)."
  type        = number
  default     = 30
  validation {
    condition     = var.object_lock_days >= 1
    error_message = "The audit bucket must have Object Lock."
  }
}

variable "audit_retention_days" {
  description = "Delete audit records after this many days. Must be longer than the lock."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags added to every resource."
  type        = map(string)
  default     = {}
}

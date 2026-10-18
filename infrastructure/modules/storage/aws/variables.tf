variable "name" {
  description = "Name prefix for resources, such as counterpart-dev."
  type        = string
}

variable "kms_key_arn" {
  description = "The project's customer managed KMS key."
  type        = string
}

variable "document_retention_days" {
  description = "How long checked documents are kept. Proposed: 3 years (Phase 2, section 8)."
  type        = number
  default     = 1095
}

variable "tags" {
  description = "Tags added to every resource."
  type        = map(string)
  default     = {}
}

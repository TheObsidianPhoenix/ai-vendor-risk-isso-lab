variable "name" {
  description = "Name prefix for tables, such as counterpart-dev."
  type        = string
}

variable "kms_key_arn" {
  description = "The project's customer managed KMS key."
  type        = string
}

variable "tags" {
  description = "Tags added to every table."
  type        = map(string)
  default     = {}
}

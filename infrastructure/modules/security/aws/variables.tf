variable "name" {
  description = "Name used for the key alias, such as counterpart-dev."
  type        = string
}

variable "tags" {
  description = "Tags added to the key."
  type        = map(string)
  default     = {}
}

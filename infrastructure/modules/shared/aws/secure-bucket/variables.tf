variable "name_prefix" {
  description = "Start of the bucket name. AWS adds a unique suffix."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]{3,37}$", var.name_prefix))
    error_message = "Use 3 to 37 lowercase letters, digits or hyphens."
  }
}

variable "purpose" {
  description = "One line saying what the bucket holds. Stored as a tag."
  type        = string
  validation {
    # S3 tag values allow only letters, numbers, spaces and _ . : / = + - @ (max 256).
    # A comma or parentheses here made CreateBucket fail with InvalidTag on the first apply.
    condition     = can(regex("^[A-Za-z0-9 _.:/=+@-]{0,256}$", var.purpose))
    error_message = "Use only letters, numbers, spaces and _ . : / = + - @ in purpose (it becomes an S3 tag)."
  }
}

variable "kms_key_arn" {
  description = "The project's customer managed KMS key."
  type        = string
}

variable "object_lock_days" {
  description = "Object Lock retention in days (governance mode). 0 = no Object Lock."
  type        = number
  default     = 0
}

variable "expire_days" {
  description = "Delete objects this many days after creation. 0 = keep."
  type        = number
  default     = 0
}

variable "noncurrent_version_days" {
  description = "Delete replaced or deleted versions after this many days."
  type        = number
  default     = 30
}

variable "extra_policy_json" {
  description = "Additional bucket policy statements, merged with the TLS-only rule."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags added to the bucket."
  type        = map(string)
  default     = {}
}

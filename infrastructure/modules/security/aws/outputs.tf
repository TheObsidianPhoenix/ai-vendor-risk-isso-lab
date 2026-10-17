output "kms_key_arn" {
  description = "ARN of the project's customer managed key."
  value       = aws_kms_key.this.arn
}

output "kms_alias" {
  description = "The key's alias."
  value       = aws_kms_alias.this.name
}

output "tables" {
  description = "Name and ARN of each table, keyed by vendors, assessments and decisions."
  value       = { for key, table in aws_dynamodb_table.this : key => { name = table.name, arn = table.arn } }
}

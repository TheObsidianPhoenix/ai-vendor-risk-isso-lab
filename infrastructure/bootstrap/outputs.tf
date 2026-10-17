output "state_bucket" {
  description = "Pass this to terraform init in environments/dev as -backend-config=\"bucket=...\"."
  value       = aws_s3_bucket.state.id
}

output "plan_role_arn" {
  description = "Role pull requests use to run terraform plan. Stored as a GitHub repository variable."
  value       = aws_iam_role.plan.arn
}

output "deploy_role_arn" {
  description = "Role the main branch uses to run terraform apply. Stored as a GitHub repository variable."
  value       = aws_iam_role.deploy.arn
}

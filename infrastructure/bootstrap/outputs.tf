output "state_bucket" {
  description = "Pass this to terraform init in environments/dev as -backend-config=\"bucket=...\"."
  value       = aws_s3_bucket.state.id
}

output "plan_role_arn" {
  description = "Role pull requests use to run terraform plan. Stored as a GitHub repository variable."
  value       = var.enable_github_oidc ? aws_iam_role.plan[0].arn : null
}

output "deploy_role_arn" {
  description = "Role the main branch uses to run terraform apply. Stored as a GitHub repository variable."
  value       = var.enable_github_oidc ? aws_iam_role.deploy[0].arn : null
}

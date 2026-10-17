output "alerts_topic_arn" {
  description = "SNS topic that receives security alerts."
  value       = aws_sns_topic.alerts.arn
}

output "security_alert_rules" {
  description = "Names of the EventBridge rules that watch for risky account changes."
  value       = [for rule in aws_cloudwatch_event_rule.security : rule.name]
}

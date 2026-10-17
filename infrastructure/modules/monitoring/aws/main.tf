# Alerts and cost guardrails (Phase 2, section 9.2; SI-4, CA-7, AU-6).
#
# Security alerts here watch the AWS account itself, using CloudTrail events
# delivered to EventBridge. They need no log processing and cost nothing at
# this volume. Application alarms (prompt injection flagged, permission
# denied, validation failures) arrive with the application functions.
#
# Note: IAM and root sign-in events are delivered only in us-east-1, so those
# two alerts need rules in that region. They're listed as a follow-up in the
# deploy runbook because the account's region guardrails must be checked first.

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name              = "${var.name}-security-alerts"
  kms_master_key_id = var.kms_key_arn
  tags              = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  # Created only when an address is supplied (never committed; see terraform.tfvars.example).
  # AWS emails a confirmation link that must be clicked before alerts arrive.
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_iam_policy_document" "alerts" {
  statement {
    sid       = "EventBridgePublishes"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts.json
}

locals {
  # Each alert: which AWS API calls, recorded by CloudTrail, should notify the ISSO.
  security_alerts = {
    cloudtrail-tampering = {
      description = "Someone stopped, deleted or changed the audit trail (MITRE ATT&CK T1562.008)"
      source      = "cloudtrail.amazonaws.com"
      events      = ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "PutInsightSelectors"]
    }
    kms-key-at-risk = {
      description = "Someone disabled the data key, scheduled it for deletion, or changed its policy"
      source      = "kms.amazonaws.com"
      events      = ["DisableKey", "ScheduleKeyDeletion", "PutKeyPolicy", "DisableKeyRotation"]
    }
    s3-protection-changed = {
      description = "A bucket's public access block, policy or encryption was changed or removed"
      source      = "s3.amazonaws.com"
      events = [
        "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
        "PutBucketPolicy", "DeleteBucketPolicy",
        "PutBucketEncryption", "DeleteBucketEncryption",
        "PutBucketOwnershipControls", "PutObjectLockConfiguration",
      ]
    }
    database-protection-changed = {
      description = "Deletion protection, backups or encryption changed on a database table"
      source      = "dynamodb.amazonaws.com"
      events      = ["UpdateTable", "DeleteTable", "UpdateContinuousBackups", "DeleteBackup"]
    }
  }
}

resource "aws_cloudwatch_event_rule" "security" {
  for_each    = local.security_alerts
  name        = "${var.name}-${each.key}"
  description = each.value.description
  tags        = var.tags
  event_pattern = jsonencode({
    source        = ["aws.${split(".", each.value.source)[0]}"] # e.g. kms.amazonaws.com -> aws.kms
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = [each.value.source]
      eventName   = each.value.events
    }
  })
}

resource "aws_cloudwatch_event_target" "security" {
  for_each = local.security_alerts
  rule     = aws_cloudwatch_event_rule.security[each.key].name
  arn      = aws_sns_topic.alerts.arn
}

# Cost guardrail: email at $5 and $10 of actual spend, and when the month is
# forecast to pass the limit (Phase 1 target: under $10 a month).
resource "aws_budgets_budget" "monthly" {
  name         = "${var.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = var.alert_email == "" ? [] : var.budget_alert_thresholds_usd
    content {
      comparison_operator        = "GREATER_THAN"
      notification_type          = "ACTUAL"
      threshold                  = notification.value
      threshold_type             = "ABSOLUTE_VALUE"
      subscriber_email_addresses = [var.alert_email]
    }
  }

  dynamic "notification" {
    for_each = var.alert_email == "" ? [] : [1]
    content {
      comparison_operator        = "GREATER_THAN"
      notification_type          = "FORECASTED"
      threshold                  = 100
      threshold_type             = "PERCENTAGE"
      subscriber_email_addresses = [var.alert_email]
    }
  }
}

# What the github-deploy role may do (AC-6, least privilege).
#
# It covers only the services the foundation layer uses, and only resources
# whose names start with "counterpart-" or that carry the Project=counterpart
# tag. Each later layer (sign-in, API, functions) adds its own permissions
# here in the same pull request that adds the resources, so every widening of
# access is reviewed.
#
# It is not AdministratorAccess on purpose: a compromised pipeline could only
# touch this project's resources, not the rest of the account.

data "aws_iam_policy_document" "deploy" {
  # --- Terraform state -------------------------------------------------------
  statement {
    sid       = "StateBucket"
    actions   = ["s3:ListBucket", "s3:GetBucketVersioning"]
    resources = [aws_s3_bucket.state.arn]
  }
  statement {
    sid       = "StateObjects"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.state.arn}/*"]
  }

  # --- Discovery: read-only calls Terraform makes while planning -------------
  statement {
    sid = "Describe"
    actions = [
      "kms:ListAliases", "kms:ListKeys",
      "s3:ListAllMyBuckets",
      "cloudtrail:DescribeTrails", "cloudtrail:ListTrails", "cloudtrail:LookupEvents",
      "dynamodb:ListTables", "dynamodb:DescribeLimits",
      "sns:ListTopics",
      "events:ListRules",
    ]
    resources = ["*"]
  }

  # --- KMS: create keys only with the project tag; manage only tagged keys ---
  statement {
    sid       = "KmsCreateTaggedKey"
    actions   = ["kms:CreateKey", "kms:TagResource"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = ["counterpart"]
    }
  }
  statement {
    sid = "KmsManageProjectKey"
    actions = [
      "kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy",
      "kms:GetKeyRotationStatus", "kms:EnableKeyRotation",
      "kms:ListResourceTags", "kms:TagResource", "kms:UntagResource",
      "kms:UpdateKeyDescription", "kms:ScheduleKeyDeletion", "kms:CreateGrant",
      "kms:GenerateDataKey", "kms:Decrypt",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = ["counterpart"]
    }
  }
  statement {
    sid     = "KmsProjectAlias"
    actions = ["kms:CreateAlias", "kms:DeleteAlias", "kms:UpdateAlias"]
    resources = [
      "arn:${local.partition}:kms:*:${local.account_id}:alias/counterpart-*",
      "arn:${local.partition}:kms:*:${local.account_id}:key/*",
    ]
  }

  # --- S3: bucket settings for project buckets, never their contents --------
  statement {
    sid       = "S3ProjectBuckets"
    actions   = ["s3:*"]
    resources = ["arn:${local.partition}:s3:::counterpart-*"]
  }
  statement {
    sid    = "S3NoProjectDataAccess"
    effect = "Deny"
    actions = [
      "s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
      "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention",
    ]
    resources = [
      "arn:${local.partition}:s3:::counterpart-*-quarantine-*/*",
      "arn:${local.partition}:s3:::counterpart-*-documents-*/*",
      "arn:${local.partition}:s3:::counterpart-*-audit-*/*",
    ]
  }

  # --- CloudTrail, DynamoDB, SNS, EventBridge, Budgets: project names only ---
  statement {
    sid       = "CloudTrailProjectTrail"
    actions   = ["cloudtrail:*"]
    resources = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/counterpart-*"]
  }
  statement {
    sid     = "DynamoDbProjectTables"
    actions = ["dynamodb:*"]
    resources = [
      "arn:${local.partition}:dynamodb:*:${local.account_id}:table/counterpart-*",
      "arn:${local.partition}:dynamodb:*:${local.account_id}:table/counterpart-*/index/*",
    ]
  }
  statement {
    sid       = "DynamoDbNoItemAccess"
    effect    = "Deny"
    actions   = ["dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem"]
    resources = ["arn:${local.partition}:dynamodb:*:${local.account_id}:table/counterpart-*"]
  }
  statement {
    sid       = "SnsProjectTopics"
    actions   = ["sns:*"]
    resources = ["arn:${local.partition}:sns:*:${local.account_id}:counterpart-*"]
  }
  statement {
    sid       = "EventBridgeProjectRules"
    actions   = ["events:*"]
    resources = ["arn:${local.partition}:events:*:${local.account_id}:rule/counterpart-*"]
  }
  statement {
    sid       = "BudgetsProjectBudget"
    actions   = ["budgets:*"]
    resources = ["arn:${local.partition}:budgets::${local.account_id}:budget/counterpart-*"]
  }
}

# Application database (Phase 2, section 5.8).
#
# Three tables, so each application role can be granted exactly one job:
#
# | Table       | Holds                                   | Written by    |
# |-------------|-----------------------------------------|---------------|
# | vendors     | Vendor records and document metadata    | api, intake   |
# | assessments | AI recommendations and scores, versioned| ai-worker     |
# | decisions   | Human decisions                         | decision only |
#
# Decisions are a separate table (HR-01) so the AI worker's role can be
# denied it outright, and the decision code writes with a condition that
# refuses to overwrite an existing record.
#
# All tables: on-demand billing (no charge when idle), encrypted with the
# project key, point-in-time recovery, and deletion protection.
#
# Retention (Phase 2, section 8): every item carries expires_at, a Unix time
# set by the application: 3 years after the item was written, with the vendor
# record pushed forward on every activity so an active vendor never expires.
# DynamoDB's built-in expiry (TTL) deletes items after that time, at no extra
# cost, so nothing is kept longer than the retention policy allows.

locals {
  tables = {
    vendors = {
      hash_key = "id"
      indexes  = { by_owner = "owner_id" }
    }
    assessments = {
      hash_key = "id"
      indexes  = { by_vendor = "vendor_id" }
    }
    decisions = {
      hash_key = "id"
      indexes  = { by_vendor = "vendor_id" }
    }
  }
}

resource "aws_dynamodb_table" "this" {
  for_each = local.tables

  name                        = "${var.name}-${each.key}"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = each.value.hash_key
  deletion_protection_enabled = true
  tags                        = merge(var.tags, { Table = each.key })

  attribute {
    name = each.value.hash_key
    type = "S"
  }

  dynamic "attribute" {
    for_each = toset(values(each.value.indexes))
    content {
      name = attribute.value
      type = "S"
    }
  }

  dynamic "global_secondary_index" {
    for_each = each.value.indexes
    content {
      name            = global_secondary_index.key
      hash_key        = global_secondary_index.value
      projection_type = "ALL"
    }
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  point_in_time_recovery {
    enabled = true
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

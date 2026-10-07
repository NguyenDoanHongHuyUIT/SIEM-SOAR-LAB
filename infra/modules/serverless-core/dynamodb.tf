# Single-table design, see src/lambdas/siemsoar/store.py for the item layout.
resource "aws_dynamodb_table" "cases" {
  name         = "${var.name_prefix}-cases"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }
  attribute {
    name = "dedup_key"
    type = "S"
  }
  attribute {
    name = "resource_id"
    type = "S"
  }
  attribute {
    name = "status"
    type = "S"
  }
  attribute {
    name = "created_at"
    type = "S"
  }

  global_secondary_index {
    name            = "dedup-index"
    hash_key        = "dedup_key"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "resource-index"
    hash_key        = "resource_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "status-index"
    hash_key        = "status"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = { Zone = "security" }
}

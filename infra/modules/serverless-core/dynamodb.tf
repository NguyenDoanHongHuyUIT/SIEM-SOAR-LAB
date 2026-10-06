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

  global_secondary_index {
    name            = "dedup-index"
    hash_key        = "dedup_key"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
  tags = { Zone = "security" }
}
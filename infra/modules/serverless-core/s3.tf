data "aws_caller_identity" "me" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.me.account_id
  region     = data.aws_region.current.name
}

# ---------------------------------------------------------------- evidence (immutable)
resource "aws_s3_bucket" "evidence" {
  bucket              = "${var.name_prefix}-evidence-${local.account_id}"
  object_lock_enabled = true
  force_destroy       = true # lets the week-12 teardown delete GOVERNANCE-locked objects (needs bypass permission)
  tags                = { Zone = "security" }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.evidence_retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "evidence_tls" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket     = aws_s3_bucket.evidence.id
  policy     = data.aws_iam_policy_document.evidence_tls.json
  depends_on = [aws_s3_bucket_public_access_block.evidence]
}

# ---------------------------------------------------------------- CloudTrail log archive
resource "aws_s3_bucket" "logs" {
  bucket        = "${var.name_prefix}-cloudtrail-${local.account_id}"
  force_destroy = true
  tags          = { Zone = "security" }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration {
      days = 30
    }
  }
}

# ---------------------------------------------------------------- rules + bootstrap artefacts
resource "aws_s3_bucket" "rules" {
  bucket        = "${var.name_prefix}-rules-${local.account_id}"
  force_destroy = true
  tags          = { Zone = "security" }
}

resource "aws_s3_bucket_versioning" "rules" {
  bucket = aws_s3_bucket.rules.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "rules" {
  bucket                  = aws_s3_bucket.rules.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "rules" {
  bucket = aws_s3_bucket.rules.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

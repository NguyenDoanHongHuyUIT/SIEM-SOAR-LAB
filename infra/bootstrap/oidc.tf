resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

locals {
  oidc_arn = aws_iam_openid_connect_provider.github.arn
  sub_key  = "token.actions.githubusercontent.com:sub"
  aud_key  = "token.actions.githubusercontent.com:aud"
}

# ---- Role PLAN: chỉ đọc, cho pull request ----
data "aws_iam_policy_document" "plan_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_arn]
    }
    condition {
      test     = "StringEquals"
      variable = local.aud_key
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = local.sub_key
      values   = ["repo:${var.github_repo}:pull_request"]
    }
  }
}

resource "aws_iam_role" "gha_plan" {
  name               = "gha-plan"
  assume_role_policy = data.aws_iam_policy_document.plan_trust.json
}

resource "aws_iam_role_policy_attachment" "plan_readonly" {
  role       = aws_iam_role.gha_plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# plan cần đọc state và ghi file lock
data "aws_iam_policy_document" "plan_state" {
  statement {
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.tfstate.arn, "${aws_s3_bucket.tfstate.arn}/*"]
  }
}

resource "aws_iam_role_policy" "plan_state" {
  role   = aws_iam_role.gha_plan.id
  policy = data.aws_iam_policy_document.plan_state.json
}

# ---- Role APPLY: chỉ job gắn Environment "lab" ----
data "aws_iam_policy_document" "apply_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_arn]
    }
    condition {
      test     = "StringEquals"
      variable = local.aud_key
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = local.sub_key
      values   = ["repo:${var.github_repo}:environment:lab"]
    }
  }
}

resource "aws_iam_role" "gha_apply" {
  name               = "gha-apply"
  assume_role_policy = data.aws_iam_policy_document.apply_trust.json
}

# Lab: dùng AdministratorAccess cho đơn giản. Ghi vào phần "giới hạn"
# của báo cáo, hoặc thu hẹp dần theo least privilege nếu còn thời gian.
resource "aws_iam_role_policy_attachment" "apply_admin" {
  role       = aws_iam_role.gha_apply.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ---- Role RULES: detection-as-code deploys (S3 release upload + SSM Run Command). Least privilege.
data "aws_iam_policy_document" "rules_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_arn]
    }
    condition {
      test     = "StringEquals"
      variable = local.aud_key
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = local.sub_key
      values   = ["repo:${var.github_repo}:environment:lab-rules"]
    }
  }
}

resource "aws_iam_role" "gha_rules" {
  name               = "gha-rules"
  assume_role_policy = data.aws_iam_policy_document.rules_trust.json
}

data "aws_iam_policy_document" "rules_perm" {
  statement {
    sid       = "UploadReleases"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["arn:aws:s3:::${var.name_prefix}-rules-${data.aws_caller_identity.me.account_id}/releases/*"]
  }
  statement {
    sid       = "ListReleases"
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.name_prefix}-rules-${data.aws_caller_identity.me.account_id}"]
  }
  statement {
    sid       = "RunDeployDocument"
    actions   = ["ssm:SendCommand"]
    resources = ["arn:aws:ssm:${var.region}::document/${var.name_prefix}-deploy-rules"]
  }
  statement {
    sid       = "TargetOnlyLabInstances"
    actions   = ["ssm:SendCommand"]
    resources = ["arn:aws:ec2:${var.region}:${data.aws_caller_identity.me.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/siemsoar:plane"
      values   = ["ondemand"]
    }
  }
  statement {
    sid       = "Observe"
    actions   = ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations", "ec2:DescribeInstances"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "rules" {
  role   = aws_iam_role.gha_rules.id
  policy = data.aws_iam_policy_document.rules_perm.json
}

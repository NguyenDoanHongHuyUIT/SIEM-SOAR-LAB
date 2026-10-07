data "aws_iam_policy_document" "ec2_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

locals {
  account_id = data.aws_caller_identity.me.account_id
  region     = data.aws_region.current.name
}

data "aws_caller_identity" "me" {}
data "aws_region" "current" {}

# ---- Wazuh manager
resource "aws_iam_role" "manager" {
  name               = "${var.name_prefix}-lab-manager"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
}

resource "aws_iam_role_policy_attachment" "manager_ssm" {
  role       = aws_iam_role.manager.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "manager" {
  statement {
    sid       = "PushActiveAlertsToEventBridge"
    actions   = ["events:PutEvents"]
    resources = [var.event_bus_arn]
  }
  statement {
    sid       = "ReadBootstrapAndRules"
    actions   = ["s3:GetObject"]
    resources = ["${var.rules_bucket_arn}/*"]
  }
  statement {
    sid       = "ListRulesBucket"
    actions   = ["s3:ListBucket"]
    resources = [var.rules_bucket_arn]
  }
  statement {
    sid       = "ReadCloudTrailArchive"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [var.logs_bucket_arn, "${var.logs_bucket_arn}/*"]
  }
  statement {
    sid       = "StoreWazuhAdminPassword"
    actions   = ["ssm:PutParameter"]
    resources = ["arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.name_prefix}/wazuh/*"]
  }
}

resource "aws_iam_role_policy" "manager" {
  name   = "wazuh-manager"
  role   = aws_iam_role.manager.id
  policy = data.aws_iam_policy_document.manager.json
}

resource "aws_iam_instance_profile" "manager" {
  name = aws_iam_role.manager.name
  role = aws_iam_role.manager.name
}

# ---- Lab host (Wazuh agent + Suricata). This is the SOAR "workload zone" target.
resource "aws_iam_role" "host" {
  name               = "${var.name_prefix}-lab-host"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
}

resource "aws_iam_role_policy_attachment" "host_ssm" {
  role       = aws_iam_role.host.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "host" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${var.rules_bucket_arn}/*"]
  }
  statement {
    actions   = ["s3:ListBucket"]
    resources = [var.rules_bucket_arn]
  }
}

resource "aws_iam_role_policy" "host" {
  name   = "lab-host"
  role   = aws_iam_role.host.id
  policy = data.aws_iam_policy_document.host.json
}

resource "aws_iam_instance_profile" "host" {
  name = aws_iam_role.host.name
  role = aws_iam_role.host.name
}

# ---- Victim IAM user for the "AWS technique" scenario. Keys are created/destroyed by the simulation run.
resource "aws_iam_user" "victim" {
  name          = "${var.iam_target_prefix}victim"
  force_destroy = true
  tags          = { owner = "lab", criticality = "low", "siemsoar:plane" = "ondemand" }
}

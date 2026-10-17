# Auto-stop timer for the on-demand plane (created by `python -m tools.labctl up|extend`).
#
# The schedule's target is the EventBridge Scheduler *universal target* arn:aws:scheduler:::aws-sdk:ec2:stopInstances,
# so when the timer fires Scheduler calls EC2 directly with this role: no Lambda, no code, nothing to patch.
# The role can only stop instances tagged siemsoar:plane=ondemand (never the SOAR/security assets).
data "aws_iam_policy_document" "scheduler_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${var.name_prefix}-lab-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_trust.json
}

data "aws_iam_policy_document" "scheduler_stop" {
  statement {
    actions   = ["ec2:StopInstances"]
    resources = ["${local.ec2_arn}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/siemsoar:plane"
      values   = ["ondemand"]
    }
  }
}

resource "aws_iam_role_policy" "scheduler" {
  name   = "stop-ondemand-lab-instances"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler_stop.json
}

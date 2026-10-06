# One deployment package, many handlers. Each function gets its own least-privilege role.
data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../../src/lambdas"
  output_path = "${path.module}/.build/lambdas.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc", ".gitkeep"]
}

locals {
  sfn_name = "${var.name_prefix}-case-workflow"
  # constructed (not referenced) so Lambda env <-> state machine definition has no dependency cycle
  sfn_arn  = "arn:aws:states:${local.region}:${local.account_id}:stateMachine:${local.sfn_name}"
  iam_arn  = "arn:aws:iam::${local.account_id}"
  ec2_arn  = "arn:aws:ec2:${local.region}:${local.account_id}"
  ssm_arn  = "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.name_prefix}/slack/*"
  lab_role = "${local.iam_arn}:role/${var.name_prefix}-lab-*"

  table_arns = [aws_dynamodb_table.cases.arn, "${aws_dynamodb_table.cases.arn}/index/*"]

  st = {
    ddb = {
      actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query"]
      resources = local.table_arns
    }
    sns = { actions = ["sns:Publish"], resources = [aws_sns_topic.notify.arn] }
    ssm = { actions = ["ssm:GetParameter"], resources = [local.ssm_arn] }
    kms_ssm = {
      actions   = ["kms:Decrypt"]
      resources = ["*"]
      conditions = [{
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["ssm.${local.region}.amazonaws.com"]
      }]
    }
    s3_raw = { actions = ["s3:PutObject"], resources = ["${aws_s3_bucket.evidence.arn}/raw/*"] }
    s3_case_rw = {
      actions   = ["s3:PutObject", "s3:GetObject"]
      resources = ["${aws_s3_bucket.evidence.arn}/cases/*"]
    }
    s3_case_ro = { actions = ["s3:GetObject"], resources = ["${aws_s3_bucket.evidence.arn}/cases/*"] }
    s3_list    = { actions = ["s3:ListBucket"], resources = [aws_s3_bucket.evidence.arn] }
    ec2_read = {
      actions   = ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "ec2:DescribeVolumes", "ec2:DescribeSnapshots"]
      resources = ["*"]
    }
    # mutating EC2 actions only on instances in the workload zone (tag), never on security-zone assets
    ec2_workload_write = {
      actions   = ["ec2:ModifyInstanceAttribute", "ec2:StopInstances", "ec2:StartInstances", "ec2:CreateTags", "ec2:DeleteTags"]
      resources = ["${local.ec2_arn}:instance/*"]
      conditions = [{
        test     = "StringEquals"
        variable = "aws:ResourceTag/siemsoar:zone"
        values   = ["workload"]
      }]
    }
    ec2_sg_attach = {
      actions   = ["ec2:ModifyInstanceAttribute", "ec2:CreateTags"]
      resources = ["${local.ec2_arn}:security-group/*", "${local.ec2_arn}:network-interface/*"]
    }
    ec2_sg_manage = {
      actions   = ["ec2:CreateSecurityGroup", "ec2:RevokeSecurityGroupEgress"]
      resources = ["${local.ec2_arn}:vpc/*", "${local.ec2_arn}:security-group/*"]
    }
    ec2_snapshot = {
      actions   = ["ec2:CreateSnapshot", "ec2:CreateTags"]
      resources = ["${local.ec2_arn}:volume/*", "arn:aws:ec2:${local.region}::snapshot/*"]
    }
    iam_user_read = {
      actions   = ["iam:GetUser", "iam:ListAccessKeys", "iam:ListUserTags"]
      resources = ["${local.iam_arn}:user/${var.iam_target_prefix}*"]
    }
    iam_user_write = {
      actions = [
        "iam:UpdateAccessKey", "iam:PutUserPolicy", "iam:DeleteUserPolicy",
        "iam:CreateAccessKey", "iam:DeleteAccessKey",
      ]
      resources = ["${local.iam_arn}:user/${var.iam_target_prefix}*"]
    }
    iam_role_session = {
      actions   = ["iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:GetRolePolicy"]
      resources = [local.lab_role]
    }
    iam_profile_read = {
      actions   = ["iam:GetInstanceProfile"]
      resources = ["${local.iam_arn}:instance-profile/${var.name_prefix}-lab-*"]
    }
    secrets_rotate = {
      actions   = ["secretsmanager:CreateSecret", "secretsmanager:PutSecretValue"]
      resources = ["arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:/${var.name_prefix}/rotated-keys/*"]
    }
    sfn_start = { actions = ["states:StartExecution"], resources = [local.sfn_arn] }
    sfn_task  = { actions = ["states:SendTaskSuccess", "states:SendTaskFailure"], resources = ["*"] }
    lab_ec2 = {
      actions   = ["ec2:StartInstances", "ec2:StopInstances"]
      resources = ["${local.ec2_arn}:instance/*"]
      conditions = [{
        test     = "StringEquals"
        variable = "aws:ResourceTag/siemsoar:plane"
        values   = ["ondemand"]
      }]
    }
    lab_ec2_read = { actions = ["ec2:DescribeInstances"], resources = ["*"] }
    lab_scheduler = {
      actions   = ["scheduler:CreateSchedule", "scheduler:DeleteSchedule", "scheduler:GetSchedule"]
      resources = ["arn:aws:scheduler:${local.region}:${local.account_id}:schedule/default/${var.name_prefix}-lab-*"]
    }
    lab_passrole = {
      actions   = ["iam:PassRole"]
      resources = [aws_iam_role.scheduler.arn]
      conditions = [{
        test     = "StringEquals"
        variable = "iam:PassedToService"
        values   = ["scheduler.amazonaws.com"]
      }]
    }
  }

  functions = {
    ingest = {
      timeout    = 30, memory = 256
      statements = [local.st.ddb, local.st.s3_raw, local.st.sfn_start]
    }
    enrich = {
      timeout    = 30, memory = 256
      statements = [local.st.ddb, local.st.ec2_read, local.st.iam_user_read]
    }
    notify = {
      timeout    = 20, memory = 256
      statements = [local.st.ddb, local.st.sns, local.st.ssm, local.st.kms_ssm]
    }
    slack_interact = {
      timeout    = 10, memory = 256
      statements = [local.st.ddb, local.st.ssm, local.st.kms_ssm, local.st.sfn_task]
    }
    preflight = {
      timeout    = 30, memory = 256
      statements = [local.st.ddb, local.st.ec2_read, local.st.ec2_workload_write, local.st.ec2_sg_attach, local.st.iam_user_read]
    }
    save_state = {
      timeout = 30, memory = 256
      statements = [
        local.st.ddb, local.st.s3_case_rw, local.st.s3_list, local.st.ec2_read, local.st.iam_user_read,
        local.st.iam_profile_read,
      ]
    }
    contain = {
      timeout = 60, memory = 256
      statements = [
        local.st.ddb, local.st.s3_case_ro, local.st.s3_list, local.st.ec2_read, local.st.ec2_workload_write,
        local.st.ec2_sg_attach, local.st.ec2_sg_manage, local.st.ec2_snapshot, local.st.iam_user_read,
        local.st.iam_user_write, local.st.iam_role_session, local.st.iam_profile_read,
      ]
    }
    restore = {
      timeout = 60, memory = 256
      statements = [
        local.st.ddb, local.st.s3_case_ro, local.st.s3_list, local.st.ec2_read, local.st.ec2_workload_write,
        local.st.ec2_sg_attach, local.st.iam_user_read, local.st.iam_user_write, local.st.iam_role_session,
        local.st.iam_profile_read, local.st.secrets_rotate,
      ]
    }
    case_ops = {
      timeout    = 30, memory = 256
      statements = [local.st.ddb, local.st.sns, local.st.ssm, local.st.kms_ssm]
    }
    lab_session = {
      timeout    = 60, memory = 128
      statements = [local.st.lab_ec2, local.st.lab_ec2_read, local.st.lab_scheduler, local.st.lab_passrole]
    }
  }

  common_env = {
    CASES_TABLE              = aws_dynamodb_table.cases.name
    EVIDENCE_BUCKET          = aws_s3_bucket.evidence.bucket
    NOTIFY_TOPIC_ARN         = aws_sns_topic.notify.arn
    STATE_MACHINE_ARN        = local.sfn_arn
    NAME_PREFIX              = var.name_prefix
    DEDUP_WINDOW_SECONDS     = tostring(var.dedup_window_seconds)
    APPROVAL_TIMEOUT_SECONDS = tostring(var.approval_timeout_seconds)
    RESTORE_TIMEOUT_SECONDS  = tostring(var.restore_timeout_seconds)
    BREAKER_LIMIT            = tostring(var.breaker_limit)
    BREAKER_WINDOW_SECONDS   = tostring(var.breaker_window_seconds)
    STOP_RISK_THRESHOLD      = tostring(var.stop_risk_threshold)
    DRY_RUN                  = tostring(var.dry_run)
    IAM_TARGET_PREFIX        = var.iam_target_prefix
    SLACK_CHANNEL            = var.slack_channel
    LOG_LEVEL                = "INFO"
  }

  lab_env = {
    LAB_NAME_PREFIX    = var.name_prefix
    SCHEDULER_ROLE_ARN = aws_iam_role.scheduler.arn
    SELF_FUNCTION_ARN  = "arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-lab_session"
  }
}

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_group" "fn" {
  for_each          = local.functions
  name              = "/aws/lambda/${var.name_prefix}-${each.key}"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "fn" {
  for_each           = local.functions
  name               = "${var.name_prefix}-fn-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

data "aws_iam_policy_document" "fn" {
  for_each = local.functions

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.fn[each.key].arn}:*"]
  }

  dynamic "statement" {
    for_each = { for i, s in each.value.statements : tostring(i) => merge({ conditions = [] }, s) }
    content {
      sid       = "S${statement.key}"
      actions   = statement.value.actions
      resources = statement.value.resources
      dynamic "condition" {
        for_each = statement.value.conditions
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }
  }
}

resource "aws_iam_role_policy" "fn" {
  for_each = local.functions
  name     = "least-privilege"
  role     = aws_iam_role.fn[each.key].id
  policy   = data.aws_iam_policy_document.fn[each.key].json
}

resource "aws_lambda_function" "fn" {
  for_each         = local.functions
  function_name    = "${var.name_prefix}-${each.key}"
  role             = aws_iam_role.fn[each.key].arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "handlers.${each.key}.handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = each.value.timeout
  memory_size      = each.value.memory

  environment {
    variables = each.key == "lab_session" ? local.lab_env : local.common_env
  }

  depends_on = [aws_cloudwatch_log_group.fn, aws_iam_role_policy.fn]
  tags       = { Zone = "security" }
}

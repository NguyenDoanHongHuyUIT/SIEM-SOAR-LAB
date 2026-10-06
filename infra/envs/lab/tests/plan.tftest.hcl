# `terraform test` with a mocked AWS provider: proves the whole configuration PLANS (for_each/dynamic blocks,
# templatefile of the state machine, user-data, IAM statements) without credentials. Run in CI: terraform -chdir=infra/envs/lab test
mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}]}"
    }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_region" {
    defaults = { name = "ap-southeast-1" }
  }
  mock_data "aws_ssm_parameter" {
    defaults = { value = "ami-0123456789abcdef0" }
  }
  mock_data "aws_availability_zones" {
    defaults = { names = ["ap-southeast-1a", "ap-southeast-1b"] }
  }
}

variables {
  alert_email = "ops@example.com"
}

run "always_on_plane_only" {
  command = plan
  variables {
    lab_enabled = false
  }
  assert {
    condition     = length(module.lab) == 0
    error_message = "on-demand plane must not exist when lab_enabled=false"
  }
  assert {
    condition     = length(module.core.cases_table) > 0
    error_message = "core plane must always exist"
  }
}

run "with_on_demand_plane" {
  command = plan
  variables {
    lab_enabled = true
  }
  assert {
    condition     = length(module.lab) == 1
    error_message = "on-demand plane must exist when lab_enabled=true"
  }
}

run "dry_run_defaults_on" {
  command = plan
  assert {
    condition     = var.dry_run == true
    error_message = "first deployments must default to dry_run"
  }
}

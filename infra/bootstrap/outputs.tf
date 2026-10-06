output "tfstate_bucket" {
  value       = aws_s3_bucket.tfstate.bucket
  description = "Set as GitHub repo variable TFSTATE_BUCKET"
}

output "github_variables" {
  description = "Create these as GitHub *repository variables*; create environments `lab` and `lab-rules`."
  value = {
    TFSTATE_BUCKET = aws_s3_bucket.tfstate.bucket
    PLAN_ROLE_ARN  = aws_iam_role.gha_plan.arn
    APPLY_ROLE_ARN = aws_iam_role.gha_apply.arn
    RULES_ROLE_ARN = aws_iam_role.gha_rules.arn
  }
}

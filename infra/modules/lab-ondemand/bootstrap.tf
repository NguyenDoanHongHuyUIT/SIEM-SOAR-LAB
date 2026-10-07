# Wazuh/Suricata configuration and helper scripts are shipped through S3 (EC2 user-data is limited to 16 KB).
locals {
  bootstrap_dirs = {
    wazuh    = "${path.module}/../../../wazuh"
    suricata = "${path.module}/../../../suricata"
    scripts  = "${path.module}/../../../scripts"
  }
  bootstrap_files = merge([
    for d, path in local.bootstrap_dirs : {
      for f in fileset(path, "**") : "${d}/${f}" => "${path}/${f}"
    }
  ]...)
}

resource "aws_s3_object" "bootstrap" {
  for_each = local.bootstrap_files
  bucket   = var.rules_bucket
  key      = "bootstrap/${each.key}"
  source   = each.value
  etag     = filemd5(each.value)
}

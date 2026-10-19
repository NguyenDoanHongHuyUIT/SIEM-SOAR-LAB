# Wazuh/Suricata configuration and helper scripts are shipped through S3 (EC2 user-data is limited to 16 KB).
locals {
  bootstrap_dirs = {
    agent    = "${path.module}/../../../agent"
    wazuh    = "${path.module}/../../../wazuh"
    suricata = "${path.module}/../../../suricata"
    scripts  = "${path.module}/../../../scripts"
  }
  bootstrap_files = merge([
    for d, path in local.bootstrap_dirs : {
      for f in fileset(path, "**") : "${d}/${f}" => "${path}/${f}" if !strcontains(f, "__pycache__")
    }
  ]...)
  # bash/python on the EC2 hosts must never see CRLF, whatever line endings the operator's checkout has (Windows
  # core.autocrlf): the uploaded content is normalised here instead of trusting the working tree.
  bootstrap_content = { for k, f in local.bootstrap_files : k => replace(file(f), "\r\n", "\n") }
}

resource "aws_s3_object" "bootstrap" {
  for_each = local.bootstrap_content
  bucket   = var.rules_bucket
  key      = "bootstrap/${each.key}"
  content  = each.value
  etag     = md5(each.value)
}

data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

locals {
  base_env = {
    region        = local.region
    prefix        = var.name_prefix
    boot_bucket   = var.rules_bucket
    wazuh_version = var.wazuh_version
  }
}

resource "aws_instance" "manager" {
  ami                    = data.aws_ssm_parameter.ubuntu.value
  instance_type          = var.manager_instance_type
  subnet_id              = aws_subnet.lab.id
  vpc_security_group_ids = [aws_security_group.manager.id]
  iam_instance_profile   = aws_iam_instance_profile.manager.name

  metadata_options {
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
  }
  root_block_device {
    volume_size = var.manager_volume_gb
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/user_data.sh.tftpl", merge(local.base_env, {
    role           = "manager"
    manager_ip     = ""
    cloudtrail_bkt = var.logs_bucket
  }))
  user_data_replace_on_change = true

  tags = {
    Name                 = "${var.name_prefix}-wazuh-manager"
    "siemsoar:role"      = "wazuh-manager"
    "siemsoar:plane"     = "ondemand"
    "siemsoar:zone"      = "security"
    "siemsoar:protected" = "true" # SOAR must never isolate the SIEM itself
  }

  lifecycle {
    ignore_changes = [ami]
  }
  depends_on = [aws_s3_object.bootstrap, aws_route_table_association.lab]
}

resource "aws_instance" "sensor" {
  ami                    = data.aws_ssm_parameter.ubuntu.value
  instance_type          = var.sensor_instance_type
  subnet_id              = aws_subnet.lab.id
  vpc_security_group_ids = [aws_security_group.sensor.id]
  iam_instance_profile   = aws_iam_instance_profile.host.name

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/user_data.sh.tftpl", merge(local.base_env, {
    role           = "sensor"
    manager_ip     = aws_instance.manager.private_ip
    cloudtrail_bkt = var.logs_bucket
  }))
  user_data_replace_on_change = true

  tags = {
    Name                  = "${var.name_prefix}-lab-host"
    "siemsoar:role"       = "suricata-sensor"
    "siemsoar:plane"      = "ondemand"
    "siemsoar:zone"       = "workload" # the only zone SOAR is allowed to contain
    criticality           = "high"
    owner                 = "lab"
    "iac:security_groups" = aws_security_group.sensor.id # desired state compared by restore validation
  }

  lifecycle {
    ignore_changes = [ami]
  }
  depends_on = [aws_s3_object.bootstrap, aws_route_table_association.lab]
}

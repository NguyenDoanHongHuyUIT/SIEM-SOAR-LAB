# ---- Target hosts (workload zone): more machines the SOAR can contain, and the destination of the cross-host Atomic
# Red Team tests that run from the sensor (T1046 port scan, T1110.004 credential stuffing). Each target has a Wazuh
# agent with the same FIM configuration as the sensor, no Suricata (the sensor sees its own traffic, so it observes the
# cross-host tests from the source side), and its OWN IAM role: containment revokes the role's older sessions, and a
# role shared by several hosts would cut every host's credentials to contain one.

resource "aws_security_group" "target" {
  name        = "${var.name_prefix}-lab-target"
  description = "Lab targets: SSH from the lab sensor only (cross-host Atomic tests); nothing from the internet"
  vpc_id      = aws_vpc.lab.id
}

resource "aws_vpc_security_group_ingress_rule" "target_ssh_from_sensor" {
  security_group_id            = aws_security_group.target.id
  referenced_security_group_id = aws_security_group.sensor.id
  from_port                    = 22
  to_port                      = 22
  ip_protocol                  = "tcp"
  description                  = "T1110.004 credential stuffing and T1046 scan from the sensor (Atomic Red Team)"
}

resource "aws_vpc_security_group_egress_rule" "target_all" {
  security_group_id = aws_security_group.target.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "package repos, AWS APIs (SSM), Wazuh manager"
}

resource "aws_vpc_security_group_ingress_rule" "target_agent_events" {
  security_group_id            = aws_security_group.manager.id
  referenced_security_group_id = aws_security_group.target.id
  from_port                    = 1514
  to_port                      = 1514
  ip_protocol                  = "tcp"
  description                  = "Wazuh agent events from the targets"
}

resource "aws_vpc_security_group_ingress_rule" "target_agent_enroll" {
  security_group_id            = aws_security_group.manager.id
  referenced_security_group_id = aws_security_group.target.id
  from_port                    = 1515
  to_port                      = 1515
  ip_protocol                  = "tcp"
  description                  = "Wazuh agent enrolment from the targets"
}

resource "aws_iam_role" "target" {
  count              = var.target_count
  name               = "${var.name_prefix}-lab-target-${count.index + 1}"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
}

resource "aws_iam_role_policy_attachment" "target_ssm" {
  count      = var.target_count
  role       = aws_iam_role.target[count.index].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "target" {
  count  = var.target_count
  name   = "lab-host"
  role   = aws_iam_role.target[count.index].id
  policy = data.aws_iam_policy_document.host.json # read the bootstrap files, as the sensor
}

resource "aws_iam_instance_profile" "target" {
  count = var.target_count
  name  = aws_iam_role.target[count.index].name
  role  = aws_iam_role.target[count.index].name
}

resource "aws_instance" "target" {
  count                  = var.target_count
  ami                    = data.aws_ssm_parameter.ubuntu.value
  instance_type          = var.target_instance_type
  subnet_id              = aws_subnet.lab.id
  vpc_security_group_ids = [aws_security_group.target.id]
  iam_instance_profile   = aws_iam_instance_profile.target[count.index].name

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
    role           = "target"
    manager_ip     = aws_instance.manager.private_ip
    cloudtrail_bkt = var.logs_bucket
  }))
  user_data_replace_on_change = true

  tags = {
    Name                  = "${var.name_prefix}-lab-target-${count.index + 1}"
    "siemsoar:role"       = "lab-target"
    "siemsoar:plane"      = "ondemand"
    "siemsoar:zone"       = "workload"
    criticality           = "medium"
    owner                 = "lab"
    "iac:security_groups" = aws_security_group.target.id # desired state compared by restore validation
  }

  lifecycle {
    ignore_changes = [ami]
  }
  depends_on = [aws_s3_object.bootstrap, aws_route_table_association.lab, aws_instance.manager]
}

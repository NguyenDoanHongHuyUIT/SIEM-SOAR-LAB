data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.name_prefix}-lab", "siemsoar:plane" = "ondemand" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.name_prefix}-lab" }
}

resource "aws_subnet" "lab" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 1, 0)
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true # outbound only (no NAT gateway cost); no inbound rules exist
  tags                    = { Name = "${var.name_prefix}-lab-public" }
}

resource "aws_route_table" "lab" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
}

resource "aws_route_table_association" "lab" {
  subnet_id      = aws_subnet.lab.id
  route_table_id = aws_route_table.lab.id
}

# Nothing is reachable from the internet. Operators use SSM Session Manager / port forwarding.
resource "aws_security_group" "manager" {
  name        = "${var.name_prefix}-lab-manager"
  description = "Wazuh manager: agent traffic from the lab host only"
  vpc_id      = aws_vpc.lab.id
}

resource "aws_security_group" "sensor" {
  name        = "${var.name_prefix}-lab-host"
  description = "Lab EC2 (Wazuh agent + Suricata): no inbound"
  vpc_id      = aws_vpc.lab.id
}

resource "aws_vpc_security_group_ingress_rule" "agent_events" {
  security_group_id            = aws_security_group.manager.id
  referenced_security_group_id = aws_security_group.sensor.id
  from_port                    = 1514
  to_port                      = 1514
  ip_protocol                  = "tcp"
  description                  = "Wazuh agent events"
}

resource "aws_vpc_security_group_ingress_rule" "agent_enroll" {
  security_group_id            = aws_security_group.manager.id
  referenced_security_group_id = aws_security_group.sensor.id
  from_port                    = 1515
  to_port                      = 1515
  ip_protocol                  = "tcp"
  description                  = "Wazuh agent enrolment"
}

resource "aws_vpc_security_group_egress_rule" "manager_all" {
  security_group_id = aws_security_group.manager.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "package repos, AWS APIs"
}

resource "aws_vpc_security_group_egress_rule" "sensor_all" {
  security_group_id = aws_security_group.sensor.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "package repos, AWS APIs, simulated traffic"
}

# ---- Containment SG used by the SOAR (found by name: siemsoar.response.ISOLATION_SG_NAME). No inbound; outbound only to
# the Wazuh manager's event port, so an isolated host stays visible to the SIEM while it is contained (what is it doing
# now? is the attacker still active?). Without this rule the agent would go silent exactly when telemetry matters most.
# SSM and package repos stay unreachable while isolated. The Lambda only creates a zero-egress fallback in VPCs that
# have no such group.
resource "aws_security_group" "isolation" {
  name        = "siemsoar-isolation"
  description = "SIEM-SOAR containment: no ingress, egress only to the Wazuh manager (1514/tcp)"
  vpc_id      = aws_vpc.lab.id
  tags        = { ManagedBy = "siemsoar" }
}

resource "aws_vpc_security_group_egress_rule" "isolation_to_manager" {
  security_group_id            = aws_security_group.isolation.id
  referenced_security_group_id = aws_security_group.manager.id
  from_port                    = 1514
  to_port                      = 1514
  ip_protocol                  = "tcp"
  description                  = "Wazuh agent events from a contained host"
}

resource "aws_vpc_security_group_ingress_rule" "agent_events_isolated" {
  security_group_id            = aws_security_group.manager.id
  referenced_security_group_id = aws_security_group.isolation.id
  from_port                    = 1514
  to_port                      = 1514
  ip_protocol                  = "tcp"
  description                  = "Wazuh agent events from a contained host"
}

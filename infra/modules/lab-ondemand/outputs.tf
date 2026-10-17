output "manager_instance_id" { value = aws_instance.manager.id }
output "sensor_instance_id" { value = aws_instance.sensor.id }
output "vpc_id" { value = aws_vpc.lab.id }
output "victim_user" { value = aws_iam_user.victim.name }
output "deploy_rules_document" { value = aws_ssm_document.deploy_rules.name }
output "dashboard_port_forward" {
  value = "aws ssm start-session --target ${aws_instance.manager.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=443,localPortNumber=8443  # then https://localhost:8443"
}

data "aws_availability_zones" "available" {}
data "aws_caller_identity" "current" {}

locals {
  name   = "sagi"
  azs    = slice(data.aws_availability_zones.available.names, 0, 2)
  region_prefix = "us-east-1"
  tags = {
    Name      = "sagi"
    Owner     = "sagi"
  }
}

################################################################################
# Random Password for OpenVPN Admin
################################################################################

resource "random_password" "openvpn_password" {
  length  = 16
  special = true
}

# Store password in AWS Systems Manager Parameter Store
resource "aws_ssm_parameter" "openvpn_password" {
  name  = "/${local.name}/openvpn/admin-password"
  type  = "SecureString"
  value = random_password.openvpn_password.result
  
  tags = local.tags
}

################################################################################
# Elastic IP for OpenVPN Server
################################################################################

resource "aws_eip" "this" {
  for_each = var.ec2_complet
  domain   = "vpc"
  
  tags = merge(local.tags, {
    Name = "${each.key}-${local.region_prefix}-eip"
  })
}

################################################################################
# IAM Role for test Instance using AWS IAM Module
################################################################################

module "iam_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "~> 5.0"

  create_role = true
  role_name   = "${local.name}-${local.region_prefix}-test-instance-role"
  role_requires_mfa = false

  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/AdministratorAccess"
  ]

  trusted_role_services = [
    "ec2.amazonaws.com"
  ]

  tags = local.tags
}

resource "aws_iam_instance_profile" "test_instance_profile" {
  name = "${local.name}-${local.region_prefix}-test-instance-profile"
  role = module.iam_role.iam_role_name
  
  tags = local.tags
}
################################################################################
# VPC Module
################################################################################
module "vpc" {
  for_each = var.vpc
  source = "terraform-aws-modules/vpc/aws"
  version  = "5.21.0"
  name = "${each.key}-${local.region_prefix}-vpc"
  cidr = lookup(each.value, "cidr", "10.0.0.0/16")

  azs                 = local.azs
  private_subnets     = [for k, v in local.azs : cidrsubnet(each.value.cidr, 8, k)]
  public_subnets      = [for k, v in local.azs : cidrsubnet(each.value.cidr, 8, k + 4)]

  private_subnet_names = ["Private Subnet One", "Private Subnet Two"]

  create_database_subnet_group  = false
  manage_default_network_acl    = false
  manage_default_route_table    = false
  manage_default_security_group = false

  enable_dns_hostnames = true
  enable_dns_support   = true

  enable_nat_gateway = true
  single_nat_gateway = true

  tags = local.tags
}

################################################################################
# security group module
################################################################################
module "vpc_sg" {
  for_each = var.vpc_sg
  source = "terraform-aws-modules/security-group/aws"

  name        = "${each.key}-${local.region_prefix}-vpc_sg"
  description = "Security group for user-service with custom ports open within VPC"
  vpc_id      = module.vpc["default"].vpc_id

  ingress_cidr_blocks      = lookup(each.value, "ingress_cidr_blocks", ["10.10.0.0/16"])
  ingress_rules            = lookup(each.value,"ingress_rules",["https-443-tcp"])
  ingress_with_cidr_blocks = lookup(each.value,"ingress_with_cidr_blocks", [])
  egress_rules             = lookup(each.value, "egress_rules", ["all-all"])
  egress_cidr_blocks       = ["0.0.0.0/0"]
}


################################################################################
# EC2 Instance Module with test Instance Support
################################################################################

module "ec2_complete" {
  for_each = var.ec2_complet
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~>5.8.0"

  name = "${each.key}-${local.region_prefix}-ec2"

  ami                    = "ami-02612c926201def10"  # OpenVPN Access Server 2.13.1
  instance_type          = "t3.small"
  availability_zone      = local.azs[0]
  subnet_id              = module.vpc["default"].public_subnets[0]
  vpc_security_group_ids = [module.vpc_sg["map"].security_group_id]

  key_name = module.key_pair.key_pair_name

  disable_api_termination = true
  disable_api_stop       = false
  create_eip             = false  
  create_iam_instance_profile = false 
  iam_instance_profile   = aws_iam_instance_profile.test_instance_profile.name

  hibernation = false  

  cpu_options = {
    core_count       = 1
    threads_per_core = 1
  }

  enable_volume_tags = true

  root_block_device = [
    {
      encrypted   = true
      volume_type = "gp3"
      throughput  = 125 
      volume_size = 20   
      kms_key_id  = aws_kms_key.this.arn
      delete_on_termination = false  # Keep the volume when instance is stopped
    },
  ]

  volume_tags = {
    Name = "openvpn-root-block"
  }

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = merge(local.tags, lookup(each.value, "tags", {}), {
    InstanceType = "t3.small"
    Purpose      = "OpenVPN-Server"
  })
}

# EIP association using the instance ID
resource "aws_eip_association" "this" {
  for_each = var.ec2_complet
  
  instance_id   = module.ec2_complete[each.key].id
  allocation_id = aws_eip.this[each.key].id

  depends_on = [module.ec2_complete]
}



################################################################################
# Key Pair Module (re-inserted so that local_file and outputs can reference it)
################################################################################

module "key_pair" {
  source = "terraform-aws-modules/key-pair/aws"
  key_name = "sagi-us-east-1-key"
  create_private_key = true
  tags = local.tags
}

# Save private key to a file with proper format (re-inserted)
resource "local_file" "private_key" {
  content         = module.key_pair.private_key_pem
  filename        = "${path.module}/${local.name}-${local.region_prefix}-key.pem"
  file_permission = "0600"
  
  # Ensure the file is created properly with correct format (using PEM (OpenSSH) format)
  provisioner "local-exec" {
    command = <<-EOF
      chmod 600 ${path.module}/${local.name}-${local.region_prefix}-key.pem
      # Verify the key format (using PEM (OpenSSH) format) and regenerate if needed
      if ! ssh-keygen -l -f ${path.module}/${local.name}-${local.region_prefix}-key.pem >/dev/null 2>&1; then
        echo "Regenerating SSH key (PEM (OpenSSH) format) from SSM..."
        aws ssm get-parameter --name '/sagi/ssh-key' --with-decryption --query 'Parameter.Value' --output text > ${path.module}/${local.name}-${local.region_prefix}-key.pem
        chmod 600 ${path.module}/${local.name}-${local.region_prefix}-key.pem
      fi
    EOF
  }
}

# Create a ready-to-use SSH script (re-inserted)
resource "local_file" "ssh_script" {
  for_each = var.ec2_complet
  
  content = templatefile("${path.module}/ssh_connect.sh.tpl", {
    key_file   = "${local.name}-${local.region_prefix}-key.pem"
    public_ip  = aws_eip.this[each.key].public_ip
    public_dns = aws_eip.this[each.key].public_dns
    instance_name = each.key
  })
  
  filename        = "${path.module}/ssh_to_${each.key}.sh"
  file_permission = "0755"
  
  depends_on = [aws_eip_association.this, local_file.private_key]
}

################################################################################
# KMS Key for EBS encryption
################################################################################

resource "aws_kms_key" "this" {
  description             = "KMS key for EBS encryption"
  deletion_window_in_days = 7
  
  tags = local.tags
}

resource "aws_kms_alias" "this" {
  name          = "alias/${local.name}-ebs-key"
  target_key_id = aws_kms_key.this.key_id
}

################################################################################
# CloudWatch Alarms for Cost Monitoring
################################################################################

resource "aws_cloudwatch_metric_alarm" "test_instance_cost" {
  for_each = var.ec2_complet
  
  alarm_name          = "${each.key}-test-cost-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "EstimatedCharges"
  namespace           = "AWS/Billing"
  period              = "86400"  # Daily
  statistic           = "Maximum"
  threshold           = lookup(each.value, "cost_threshold", "10")  # $10 
  alarm_description   = "This metric monitors estimated charges for test instance"
  
  dimensions = {
    Currency = "USD"
  }
  
  tags = local.tags
}

vpc = {
  default = {
    cidr = "10.0.0.0/16"
  }
}

vpc_sg = {
  map = {
    ingress_rules = ["https-443-tcp", "ssh-tcp"]
    ingress_with_cidr_blocks = [
      {
        from_port   = 943
        to_port     = 943
        protocol    = "tcp"
        description = "OpenVPN Access Server Admin UI"
        cidr_blocks = "0.0.0.0/0"
      },
      {
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        description = "OpenVPN Access Server Client UI"
        cidr_blocks = "0.0.0.0/0"
      },
      {
        from_port   = 1194
        to_port     = 1194
        protocol    = "udp"
        description = "OpenVPN UDP"
        cidr_blocks = "0.0.0.0/0"
      },
      {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        description = "SSH"
        cidr_blocks = "0.0.0.0/0"  # Restrict this to your IP for security
      }
    ]
    egress_rules = ["all-all"]  # Allow all outbound traffic
  }
}

# Optimized EC2 configuration for maximum cost savings
ec2_complet = {
  openvpn_server = {
    instance_type = "t3.micro"
    spot_price = "0.0052"  # $0.002/hour 
    # Enable fallback instances for better availability
    enable_fallback_instances = true
    # Cost monitoring threshold (alert if monthly cost exceeds this)
    cost_threshold = "5"  # $5/month threshold
    
    tags = {
      Name        = "OpenVPN-Access-Server-Spot"
      Purpose     = "VPN-Gateway"
      CostCenter  = "Infrastructure"
      Environment = "Production"
      SpotInstance = "true"
    }
  }
}

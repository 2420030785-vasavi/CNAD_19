terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-southeast-2"
}

data "aws_caller_identity" "current" {}

# Finds the latest Amazon Linux 2023 image
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Firewall for the server. No inbound rules, so port 22 starts CLOSED.
# Later you open port 22 by hand in the console to create "drift".
# ingress = [] ensures Terraform explicitly enforces zero inbound rules.
resource "aws_security_group" "watchdog_sg" {
  name        = "watchdog-sg"
  description = "Watchdog demo security group - no inbound access"

  ingress = []

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "watchdog-sg"
  }
}

resource "aws_instance" "app_server" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.watchdog_sg.id]

  tags = {
    Name = "watchdog-demo-server"
  }
}

resource "aws_s3_bucket" "data_bucket" {
  bucket = "watchdog-demo-${data.aws_caller_identity.current.account_id}"
}

output "instance_id" {
  value = aws_instance.app_server.id
}

output "security_group_id" {
  value = aws_security_group.watchdog_sg.id
}

output "bucket_name" {
  value = aws_s3_bucket.data_bucket.bucket
}

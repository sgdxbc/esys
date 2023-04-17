terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

resource "aws_vpc" "esys-entropy" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
}

resource "aws_subnet" "esys-entropy" {
  vpc_id                  = resource.aws_vpc.esys-entropy.id
  cidr_block              = "10.0.0.0/16"
  map_public_ip_on_launch = true
}

resource "aws_internet_gateway" "esys-entropy" {
  vpc_id = resource.aws_vpc.esys-entropy.id
}

resource "aws_route_table" "esys-entropy" {
  vpc_id = resource.aws_vpc.esys-entropy.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = resource.aws_internet_gateway.esys-entropy.id
  }
}

resource "aws_route_table_association" "_1" {
  route_table_id = resource.aws_route_table.esys-entropy.id
  subnet_id      = resource.aws_subnet.esys-entropy.id
}

resource "aws_security_group" "esys-entropy" {
  vpc_id = resource.aws_vpc.esys-entropy.id

  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

variable "instance_type" {
  type    = string
  default = "r5.8xlarge"
}

variable "instance_count" {
  type    = number
  default = 5
}

resource "aws_instance" "esys-entropy" {
  count = var.instance_count

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = resource.aws_subnet.esys-entropy.id
  vpc_security_group_ids = [resource.aws_security_group.esys-entropy.id]
  key_name               = "Ephemeral"
}

output "instances" {
  value = zipmap(resource.aws_instance.esys-entropy[*].public_ip, resource.aws_instance.esys-entropy[*].public_dns)
}

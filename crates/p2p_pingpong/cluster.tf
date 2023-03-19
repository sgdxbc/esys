terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  alias = "ap-east-1"
  region = "ap-east-1"
}

resource "aws_vpc" "esys-pingpong" {
  provider = aws.ap-east-1

  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "esys-pingpong" {
  provider = aws.ap-east-1

  vpc_id = resource.aws_vpc.esys-pingpong.id
  cidr_block = "10.0.0.0/16"
  map_public_ip_on_launch = true
}

resource "aws_internet_gateway" "esys-pingpong" {
  provider = aws.ap-east-1

  vpc_id = resource.aws_vpc.esys-pingpong.id
}

resource "aws_route_table" "esys-pingpong" {
  provider = aws.ap-east-1

  vpc_id = resource.aws_vpc.esys-pingpong.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = resource.aws_internet_gateway.esys-pingpong.id
  }
}

resource "aws_route_table_association" "_1" {
  provider = aws.ap-east-1

  route_table_id = resource.aws_route_table.esys-pingpong.id
  subnet_id = resource.aws_subnet.esys-pingpong.id
}

resource "aws_security_group" "esys-pingpong" {
  provider = aws.ap-east-1

  vpc_id = resource.aws_vpc.esys-pingpong.id

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
  provider = aws.ap-east-1

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

resource "aws_instance" "esys-pingpong" {
  provider = aws.ap-east-1
  count = 2

  ami = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  subnet_id = resource.aws_subnet.esys-pingpong.id
  vpc_security_group_ids = [resource.aws_security_group.esys-pingpong.id]
  key_name = "Ephemeral"
}

output "address" {
  value = resource.aws_instance.esys-pingpong[*].public_ip
}

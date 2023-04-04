terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  alias  = "ap-east-1"
  region = "ap-east-1"
}

provider "aws" {
  alias  = "ap-southeast-1"
  region = "ap-southeast-1"
}

provider "aws" {
  alias  = "us-west-1"
  region = "us-west-1"
}

module "service" {
  source = "./region"
  providers = {
    aws = aws.ap-east-1
  }

  instance_type = "t3.micro"
}

module "region-1" {
  source = "./region"
  providers = {
    aws = aws.ap-southeast-1
  }
}

module "region-2" {
  source = "./region"
  providers = {
    aws = aws.us-west-1
  }
}

resource "local_file" "inventory" {
  content = templatefile(
    "${path.module}/inventory.ini.tpl", {
      service       = module.service.ip,
      service-host  = module.service.dns,
      region-1      = module.region-1.ip,
      region-1-host = module.region-1.dns,
      region-2      = module.region-2.ip,
      region-2-host = module.region-2.dns,
  })
  filename = "../../../inventory.ini"
}

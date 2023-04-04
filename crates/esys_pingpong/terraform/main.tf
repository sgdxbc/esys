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

module "region-1" {
  source = "./region"
  providers = {
    aws = aws.ap-east-1
  }
}

module "region-2" {
  source = "./region"
  providers = {
    aws = aws.ap-southeast-1
  }
}

output "dns-1" {
  value = module.region-1.dns
}

output "dns-2" {
  value = module.region-2.dns
}

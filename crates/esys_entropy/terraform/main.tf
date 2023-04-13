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

provider "aws" {
  alias  = "eu-central-1"
  region = "eu-central-1"
}

provider "aws" {
  alias  = "sa-east-1"
  region = "sa-east-1"
}

provider "aws" {
  alias  = "af-south-1"
  region = "af-south-1"
}

module "service" {
  source = "./region"
  providers = {
    aws = aws.ap-east-1
  }

  instance_type = "r5.large"
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

module "region-3" {
  source = "./region"
  providers = {
    aws = aws.eu-central-1
  }
}

module "region-4" {
  source = "./region"
  providers = {
    aws = aws.sa-east-1
  }
}

module "region-5" {
  source = "./region"
  providers = {
    aws = aws.af-south-1
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
      region-3      = module.region-3.ip,
      region-3-host = module.region-3.dns,
      region-4      = module.region-4.ip,
      region-4-host = module.region-4.dns,
      region-5      = module.region-5.ip,
      region-5-host = module.region-5.dns,
  })
  filename = "../../../inventory.ini"
}

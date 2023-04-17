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
    aws = aws.ap-southeast-1
  }

  instance_type  = "m5.2xlarge"
  instance_count = 1
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

# ultra low latency setup for dev
# module "region-1" {
#   source = "./region"
#   providers = {
#     aws = aws.ap-east-1
#   }
# }

# module "region-2" {
#   source = "./region"
#   providers = {
#     aws = aws.ap-east-1
#   }
# }

# module "region-3" {
#   source = "./region"
#   providers = {
#     aws = aws.ap-east-1
#   }
# }

# module "region-4" {
#   source = "./region"
#   providers = {
#     aws = aws.ap-east-1
#   }
# }

# module "region-5" {
#   source = "./region"
#   providers = {
#     aws = aws.ap-east-1
#   }
# }


resource "local_file" "inventory" {
  content = templatefile(
    "${path.module}/inventory.ini.tftpl", {
      service       = module.service.instances,
      region-1      = module.region-1.instances,
      region-2      = module.region-2.instances,
      region-3      = module.region-3.instances,
      region-4      = module.region-4.instances,
      region-5      = module.region-5.instances,
  })
  filename = "${path.module}/inventory.ini"
}

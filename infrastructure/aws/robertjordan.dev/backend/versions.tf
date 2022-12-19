terraform {
  backend "s3" {
    bucket         = "robertjordan.dev-tfstate"
    dynamodb_table = "robertjordan.dev-tflock"
    key            = "terraform.tfstate"
    region         = "us-west-1"
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}
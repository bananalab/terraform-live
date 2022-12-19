module "backend_s3_bucket" {
  source             = "github.com/bananalab/terraform-modules//modules/aws-s3-bucket?ref=v0.3.1"
  bucket             = "robertjordan.dev-tfstate"
  enable_replication = false
  logging_enabled    = false
}

resource "aws_dynamodb_table" "this" {
  name           = "robertjordan.dev-tflock"
  billing_mode   = "PROVISIONED"
  hash_key       = "LockID"
  read_capacity  = 20
  write_capacity = 20
  attribute {
    name = "LockID"
    type = "S"
  }
}
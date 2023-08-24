provider "aws" {
  region = "ca-central-1" //Canada
#  skip_credentials_validation = true
#  skip_requesting_account_id  = true
#  access_key                  = "mock_access_key"
#  secret_key                  = "mock_secret_key"
}

# Create a VPC to launch our instances into
resource "aws_vpc" "acqa-test-vpc1" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = format("%s-vpc1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

# Create a security group with most of the vulnerabilities
resource "aws_security_group" "acqa-test-securitygroup1" {
  name        = "acqa-test-securitygroup1"
  description = "This security group is for API test automation"
  vpc_id      = aws_vpc.acqa-test-vpc1.id

  tags = {
    Name = format("%s-securitygroup1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }

  # SSH access from anywhere..
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }
  ingress {
    from_port   = 9020
    to_port     = 9020
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/24"]
  }

  # HTTP access from the VPC - changed
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/24"]
  }

  ingress {
    to_port     = 3306
    from_port   = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/24"]
  }
  
  # Drift 2
  ingress {
    to_port     = 3333
    from_port   = 3333
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/24"]
  }
  
  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/24"]
  }
}

# Create an internet gateway to give our subnet access to the outside world
resource "aws_internet_gateway" "acqa-test-gateway1" {
  vpc_id = aws_vpc.acqa-test-vpc1.id
  tags = {
    Name = format("%s-gateway1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

# Create a subnet to launch our instances into
resource "aws_subnet" "acqa-test-subnet1" {
  vpc_id                  = aws_vpc.acqa-test-vpc1.id
  cidr_block              = "10.0.0.0/24"
  availability_zone = "ca-central-1a"
  map_public_ip_on_launch = true
  tags = {
    Name = format("%s-subnet1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

# Create network interface
resource "aws_network_interface" "acqa-test-networkinterface1" {
  subnet_id       = aws_subnet.acqa-test-subnet1.id
  private_ips     = ["10.0.0.50"]
  security_groups = [aws_security_group.acqa-test-securitygroup1.id]

  # attachment {
  #   instance     = aws_instance.acqa-test-instance1.id
  #   device_index = 1
  # }
  tags = {
    Name = format("%s-networkinterface1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

# Get the userID for s3 bucket
# data "aws_canonical_user_id" "current_user" {}

# Create S3 bucket
resource "aws_s3_bucket" "acqa-test-s3bucket1" {
  bucket = "acqa-test-s3bucket1"
  tags = {
    Name = format("%s-s3bucket1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

# Create acl resource to grant permissions on bucket
resource "aws_s3_bucket_acl" "acqa-test-s3bucketAcl" {
  bucket = aws_s3_bucket.acqa-test-s3bucket1.id
  acl    = "private"
}

# Create acl resource to grant permissions on bucket
resource "aws_s3_bucket_acl" "acqa-test-s3bucketAcl-test-webhook2" {
  bucket = aws_s3_bucket.acqa-test-s3bucket1.id
  acl    = "private"
}

# Create IAM role for lamda
resource "aws_iam_role" "acqa-test-iamrole1" {
  name = "acqa-test-iamrole1"
  tags = {
    Name = format("%s-iamrole1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

# Create lambda function
resource "aws_lambda_function" "acqa-test-lambda1" {
  tags = {
    Name = format("%s-lamda1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }

  filename      = "acqa-test-lambda1.zip"
  function_name = "acqa-test-lambda1"
  role          = aws_iam_role.acqa-test-iamrole1.arn
  handler       = "exports.test"

  # The filebase64sha256() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
  # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
  source_code_hash = filebase64sha256("acqa-test-lambda1.zip")

  runtime = "nodejs12.x"

  environment {
    variables = {
      foo = "bar"
    }
  }
}

# # START ------------------- CODE BUILD PROJECT -------------------
# module "acqa-test-cbmodule1" {

#   source = "git::https://github.com/lgallard/terraform-aws-codebuild.git?ref=0.3.0"

#   name        = "acqa-test-cbmodule1"
#   description = "Codebuild for deploying acqa-test-module1 app with variables"

#   # CodeBuild Source
#   codebuild_source_version = "master"

#   codebuild_source_type                                   = "GITHUB"
#   codebuild_source_location                               = "https://github.com/lgallard/codebuild-example.git"
#   codebuild_source_git_clone_depth                        = 1
#   codebuild_source_git_submodules_config_fetch_submodules = true

#   # Environment
#   environment_compute_type    = "BUILD_GENERAL1_SMALL"
#   environment_image           = "aws/codebuild/standard:2.0"
#   environment_type            = "LINUX_CONTAINER"
#   environment_privileged_mode = true

#   # Environment variables
#   environment_variables = [
#     {
#       name  = "REGISTRY_URL"
#       value = "012345678910.dkr.ecr.ca-central-1.amazonaws.com/acqa-test-cbmodule1-ecr"
#     },
#     {
#       name  = "AWS_CANADA"
#       value = "ca-central-1"
#     },
#   ]

#   # Artifacts
#   artifacts_location  = aws_s3_bucket.acqa-test-s3bucket1.bucket
#   artifacts_type      = "S3"
#   artifacts_path      = "/"
#   artifacts_packaging = "ZIP"

#   # Cache
#   cache_type     = "S3"
#   cache_location = aws_s3_bucket.acqa-test-s3bucket1.bucket

#   # Logs
#   s3_logs_status   = "ENABLED"
#   s3_logs_location = "${aws_s3_bucket.acqa-test-s3bucket1.id}/build-var-log"


#   # Tags
#   tags = {
#     Name = format("%s-module1", var.acqaPrefix)
#     ACQAResource = "true"
#     Owner = "ACQA"
#   }

# }
# #END ------------------- CODE BUILD PROJECT -------------------

# # Create data pipeline
# resource "aws_datapipeline_pipeline" "acqa-test-datapipeline1" {
#   name = "acqa-test-datapipeline1"
#   # Tags
#   tags = {
#     Name = format("%s-datapipeline1", var.acqaPrefix)
#     ACQAResource = "true"
#     Owner = "ACQA"
#   }
# }

# # Create devicefarm - this is allowed in us-west-2 only
# resource "aws_devicefarm_project" "acqa-test-devicefarm1" {
#   name = "acqa-test-devicefarm1"
# }

# # Cloudformation
# resource "aws_cloudformation_stack" "acqa-test-cfntfstack1" {
#   name = "acqa-test-cfntfstack1"

#   template_body = <<STACK
#   "Resources" : {
#     "acqatestnetworkacl1cfnstack1" : {
#       "Type" : "AWS::EC2::NetworkAcl",
#       "Properties" : {
#         "VpcId" : {"Ref" : "${aws_vpc.acqa-test-vpc1.id}"},
#         "Tags" : [ {"Key" : "Name", "Value" : "acqatestnetworkacl1cfnstack1"},{"Key" : "ACQAResource", "Value" : "true"} ]
#       }
#     }
#   }
# STACK
# # Tags
#   tags = {
#     Name = format("%scfntfstack1", var.acqaPrefix)
#     ACQAResource = "true"
#     Owner = "ACQA"
#   }
# }

# Cloudwatch log group and stream
resource "aws_cloudwatch_log_group" "acqa-test-cwlg2" {
  name = "acqa-test-cwlg2"

  # Tags
  tags = {
    Name = format("%s-cwlg1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}
resource "aws_cloudwatch_log_stream" "acqa-test-cwstream1" {
  name           = "acqa-test-cwstream1"
  log_group_name = aws_cloudwatch_log_group.acqa-test-cwlg2.name
}


#Create EC2
data "aws_ami" "acqa-test-instance1-ami" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

# KMS Key
resource "aws_kms_key" "acqa-test-kmskey1" {
  description             = "acqa-test-kmskey1"
  deletion_window_in_days = 30
  tags = {
    Name = format("%s-kmskey1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

# ebs volume
resource "aws_ebs_volume" "acqa-test-ebsvolume1" {
  availability_zone = "ca-central-1a"
  size              = 25
  encrypted         = false
  tags = {
    Name = format("%s-ebsvolume1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

# EIP
resource "aws_eip" "acqa-test-eip1" {
  vpc                       = true
  network_interface         = aws_network_interface.acqa-test-networkinterface1.id
  associate_with_private_ip = "10.0.0.50"
  tags = {
    Name = format("%s-eip1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

# ec2
resource "aws_instance" "acqa-test-instance1" {
  ami           = data.aws_ami.acqa-test-instance1-ami.id
  instance_type = "t2.medium"

   network_interface {
    network_interface_id = aws_network_interface.acqa-test-networkinterface1.id
    device_index         = 0
  } 

  tags = {
    Name = format("%s-instance1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}
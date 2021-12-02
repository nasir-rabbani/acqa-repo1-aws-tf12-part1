provider "aws" {
  region = "ca-central-1" //Canada
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
    cidr_blocks = ["0.0.0.0/24"]
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
data "aws_canonical_user_id" "current_user" {}

# Create S3 bucket
resource "aws_s3_bucket" "acqa-test-s3bucket1" {
  bucket = "acqa-test-s3bucket1"

  grant {
    id          = data.aws_canonical_user_id.current_user.id
    type        = "CanonicalUser"
    permissions = ["FULL_CONTROL"]
  }

  grant {
    type        = "Group"
    permissions = ["READ", "WRITE"]
    uri         = "http://acs.amazonaws.com/groups/s3/LogDelivery"
  }

  tags = {
    Name = format("%s-s3bucket1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
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

# START ------------------- CODE BUILD PROJECT -------------------
module "acqa-test-cbmodule1" {

  source = "git::https://github.com/lgallard/terraform-aws-codebuild.git?ref=0.3.0"

  name        = "acqa-test-cbmodule1"
  description = "Codebuild for deploying acqa-test-module1 app with variables"

  # CodeBuild Source
  codebuild_source_version = "master"

  codebuild_source_type                                   = "GITHUB"
  codebuild_source_location                               = "https://github.com/lgallard/codebuild-example.git"
  codebuild_source_git_clone_depth                        = 1
  codebuild_source_git_submodules_config_fetch_submodules = true

  # Environment
  environment_compute_type    = "BUILD_GENERAL1_SMALL"
  environment_image           = "aws/codebuild/standard:2.0"
  environment_type            = "LINUX_CONTAINER"
  environment_privileged_mode = true

  # Environment variables
  environment_variables = [
    {
      name  = "REGISTRY_URL"
      value = "012345678910.dkr.ecr.ca-central-1.amazonaws.com/acqa-test-cbmodule1-ecr"
    },
    {
      name  = "AWS_CANADA"
      value = "ca-central-1"
    },
  ]

  # Artifacts
  artifacts_location  = aws_s3_bucket.acqa-test-s3bucket1.bucket
  artifacts_type      = "S3"
  artifacts_path      = "/"
  artifacts_packaging = "ZIP"

  # Cache
  cache_type     = "S3"
  cache_location = aws_s3_bucket.acqa-test-s3bucket1.bucket

  # Logs
  s3_logs_status   = "ENABLED"
  s3_logs_location = "${aws_s3_bucket.acqa-test-s3bucket1.id}/build-var-log"


  # Tags
  tags = {
    Name = format("%s-module1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }

}
# END ------------------- CODE BUILD PROJECT -------------------

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

# Cloudformation
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
resource "aws_cloudwatch_log_group" "acqa-test-cwlg1" {
  name = "acqa-test-cwlg1"

  # Tags
  tags = {
    Name = format("%s-cwlg1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}
resource "aws_cloudwatch_log_stream" "acqa-test-cwstream1" {
  name           = "acqa-test-cwstream1"
  log_group_name = aws_cloudwatch_log_group.acqa-test-cwlg1.name
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
  instance_type = "t2.micro"

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

# # EBS to EC2 attachment
# resource "aws_volume_attachment" "acqa-test-ebsattachment1" {
#   device_name = "/dev/sdh"
#   volume_id   = aws_ebs_volume.acqa-test-ebsvolume1.id
#   instance_id = aws_instance.acqa-test-instance1.id
# }

# # EIP attachment
# resource "aws_eip_association" "eip_assoc" {
#   instance_id   = aws_instance.acqa-test-instance1.id
#   allocation_id = aws_eip.acqa-test-eip1.id
# }

# Create 2 subnets for ALB
resource "aws_subnet" "acqa-test-albsubnet1" {
  vpc_id                  = aws_vpc.acqa-test-vpc1.id
  cidr_block              = "10.0.44.0/24"
  map_public_ip_on_launch = true
  tags = {
    Name = format("%s-albsubnet1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}
resource "aws_subnet" "acqa-test-albsubnet2" {
  vpc_id                  = aws_vpc.acqa-test-vpc1.id
  cidr_block              = "10.0.38.0/24"
  map_public_ip_on_launch = true
  availability_zone = "ca-central-1d"
  tags = {
    Name = format("%s-albsubnet2", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

# Create ALB
resource "aws_lb" "acqa-test-alb1" {
  name               = "acqa-test-alb1"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.acqa-test-securitygroup1.id]
  subnets            = [aws_subnet.acqa-test-albsubnet1.id, aws_subnet.acqa-test-albsubnet2.id]

  enable_deletion_protection = false

  tags = {
    Name = format("%s-alb1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

# START -------------- Autoscaling Group
resource "aws_placement_group" "acqa-test-placementgroup1" {
  name     = "acqa-test-placementgroup1"
  strategy = "partition"

  tags = {
    Name = format("%s-placementgroup1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

resource "aws_launch_configuration" "acqa-test-launchconfig1" {
  name          = "acqa-test-launchconfig1"
  # image_id      = data.aws_ami.acqa-test-instance1-ami.id
  image_id      = "ami-0ad340a3355388c70"
  instance_type = "t2.micro"
}

resource "aws_autoscaling_group" "acqa-test-asg1" {
  name                      = "acqa-test-asg1"
  max_size                  = 1
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "EC2"
  wait_for_capacity_timeout = "0"
  desired_capacity          = 1
  force_delete              = true
  placement_group           = aws_placement_group.acqa-test-placementgroup1.id
  launch_configuration      = aws_launch_configuration.acqa-test-launchconfig1.name
  vpc_zone_identifier       = [aws_subnet.acqa-test-albsubnet1.id, aws_subnet.acqa-test-albsubnet2.id]

  initial_lifecycle_hook {
    name                 = "aqa-test-asg1-lifecyclehook1"
    default_result       = "CONTINUE"
    heartbeat_timeout    = 2000
    lifecycle_transition = "autoscaling:EC2_INSTANCE_LAUNCHING"
    notification_metadata = <<EOF
{
  "foo": "bar"
}
EOF

    # notification_target_arn = "arn:aws:sqs:us-east-1:444455556666:queue1*"
    # role_arn                = "arn:aws:iam::123456789012:role/S3Access"
  }

  timeouts {
    delete = "15m"
  }

  tag {
    key                 = "Name"
    value               = format("%s-asg1", var.acqaPrefix)
    propagate_at_launch = false
  }
  tag {
    key                 = "ACQAResource"
    value               = "true"
    propagate_at_launch = false
  }
}

# Start -------------- Dynamodb table
resource "aws_dynamodb_table" "acqa-test-dynamodbtable1" {
  name             = "acqa-test-dynamodbtable1"
  hash_key         = "TestTableHashKey"
  billing_mode     = "PAY_PER_REQUEST"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "TestTableHashKey"
    type = "S"
  }
  server_side_encryption {
    enabled     = false
  }
  tags = {
    Name = format("%s-dynamodbtable1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

# Start -------------- Cloudfront
resource "aws_cloudfront_origin_access_identity" "acqa-test-oai1" {
  comment = "acqa-test-oai1"
}

resource "aws_cloudfront_distribution" "acqa-test-cloudfront1" {
  origin {
    domain_name = aws_s3_bucket.acqa-test-s3bucket1.bucket_regional_domain_name
    origin_id   = aws_cloudfront_origin_access_identity.acqa-test-oai1.cloudfront_access_identity_path

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.acqa-test-oai1.cloudfront_access_identity_path
    }
  }

  enabled             = false
  is_ipv6_enabled     = false
  comment             = "acqa-test-cloudfront1"
  default_root_object = "index.html"

  # aliases = ["acqa.accurics.com"]

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = aws_cloudfront_origin_access_identity.acqa-test-oai1.cloudfront_access_identity_path

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = aws_cloudfront_origin_access_identity.acqa-test-oai1.cloudfront_access_identity_path

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = false
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = aws_cloudfront_origin_access_identity.acqa-test-oai1.cloudfront_access_identity_path

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE"]
    }
  }

  tags = {
    Name = format("%s-cloudfront1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }

  viewer_certificate {
    cloudfront_default_certificate = false
    ssl_support_method             = "sni-only"
    # Must use us-east-1 for your Certs (certificate manager)
    acm_certificate_arn = "arn:aws:acm:us-east-1:641885301384:certificate/b5b12158-c4cd-4662-bc04-ecfe18a1bdc3"
  }
}

# Codecommit
resource "aws_codecommit_repository" "acqa-test-ccrepo1" {
  repository_name = "acqa-test-ccrepo1"
  description     = "acqa-test-ccrepo1"
  tags = {
    Name = format("%s-cloudfront1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

#Elastic Beanstalk App
resource "aws_elastic_beanstalk_application" "acqa-test-elasticbeanstalkapp1" {
  name        = "acqa-test-elasticbeanstalkapp1"
  description = "acqa-test-elasticbeanstalkapp1"

  appversion_lifecycle {
    service_role          = aws_iam_role.acqa-test-iamrole1.arn
    max_count             = 128
    delete_source_from_s3 = true
  }
  tags = {
    # Name = format("%s-elasticbeanstalkapp1", var.acqaPrefix) - This is reserved
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

# ECR
resource "aws_ecr_repository" "acqa-test-ecr1" {
  name                 = "acqa-test-ecr1"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
  tags = {
    Name = format("%s-ecr1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

#ECS Cluster
resource "aws_ecs_cluster" "acqa-test-ecs1" {
  name = "acqa-test-ecs1"
  tags = {
    Name = format("%s-ecs1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  } 
}

# EKS
resource "aws_eks_cluster" "acqa-test-eksclstr1" {
  name     = "acqa-test-eksclstr1"
  role_arn = "arn:aws:iam::641885301384:role/AccuricsEKSMgmtRole"

  tags = {
    ACQAResource = "true"
    Name         = "acqa-test-eksclstr1"
  }

  version = "1.17"

  vpc_config {
    endpoint_private_access = "true"
    endpoint_public_access  = "false"
    security_group_ids      = [aws_security_group.acqa-test-securitygroup1.id]
    subnet_ids              = [aws_subnet.acqa-test-subnet1.id, aws_subnet.acqa-test-albsubnet2.id]
  }
}

# Elastic Cache Cluster
resource "aws_elasticache_cluster" "acqa-test-elasticcachecluster1" {
  cluster_id           = "acqa-test-elasticcachecluster1"
  engine               = "memcached"
  node_type            = "cache.m4.large"
  num_cache_nodes      = 1
  parameter_group_name = "default.memcached1.5"
  port                 = 11211
  tags = {
    Name = format("%s-elasticcachecluster1", var.acqaPrefix)
    ACQAResource = "true"
    Owner = "ACQA"
  }
}

# ---------- Start Elastic Search Domain
# data "aws_caller_identity" "current" {}
# data "aws_region" "current" {}
# resource "aws_iam_service_linked_role" "acqa-test-linkedrole1" {
#   aws_service_name = "es.amazonaws.com"
# }
# resource "aws_elasticsearch_domain" "acqa-test-esdomain1" {
#   domain_name           = "acqa-test-esdomain1"
#   elasticsearch_version   = "6.5"
#   cluster_config {
#     instance_type    = "m4.large.elasticsearch"
#   }
#   timeouts {
#     update = "3s"
#     create = "3s"
#      delete = "3s"
#    }
#   vpc_options {
#     subnet_ids = [
#       aws_subnet.acqa-test-subnet1.id,
#     ]

#     security_group_ids = [aws_security_group.acqa-test-securitygroup1.id]
#   }
#   node_to_node_encryption {
#     enabled = true
#   }
#   encrypt_at_rest {
#     enabled = true
#   }
#   # advanced_security_options{
#   #   enabled = true
#   # }
#   domain_endpoint_options {
#     enforce_https = true
#     tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
#   }
#   access_policies = <<CONFIG
#   {
#     "Version": "2012-10-17",
#     "Statement": [
#         {
#             "Action": "es:*",
#             "Principal": "*",
#             "Effect": "Allow",
#             "Resource": "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/acqa-test-esdomain1/*"
#         }
#     ]
#   }
#   CONFIG
#   ebs_options{
#     ebs_enabled = true
#     volume_size = 10
#   }
#   snapshot_options {
#     automated_snapshot_start_hour = 23
#   }
#   tags = {
#     Name = format("%s-esdomain1", var.acqaPrefix)
#     ACQAResource = "true"
#     Owner = "ACQA"
#   }
#   depends_on = [aws_iam_service_linked_role.acqa-test-linkedrole1]
# }

# Access Analyzer
resource "aws_accessanalyzer_analyzer" "acqa-test-iamaccessanalyzer1" {
  analyzer_name = "acqa-test-iamaccessanalyzer1"

  tags = {
    ACQAResource = "true"
    Name = format("%s-iamaccessanalyzer1", var.acqaPrefix)
  }

  type = "ACCOUNT"
}

#Kinesis Stream
resource "aws_kinesis_stream" "acqa-test-kinessisds1" {
  arn              = "arn:aws:kinesis:ca-central-1:641885301384:stream/acqa-test-kinessisds1"
  encryption_type  = "NONE"
  name             = "acqa-test-kinessisds1"
  retention_period = "24"
  shard_count      = "1"
}

#START ---------- KINESIS FIREHOSE
resource "aws_kinesis_firehose_delivery_stream" "acqa-test-kinesisfirehoseds1" {
  arn            = "arn:aws:firehose:ca-central-1:641885301384:deliverystream/acqa-test-kinesisfirehoseds1"
  destination    = "extended_s3"
  destination_id = "destinationId-000000000001"

  extended_s3_configuration {
    bucket_arn      = "arn:aws:s3:::acqa-test-s3bucket1"
    buffer_interval = "900"
    buffer_size     = "5"

    cloudwatch_logging_options {
      enabled         = "true"
      log_group_name  = "/aws/kinesisfirehose/acqa-test-kinesisfirehoseds1"
      log_stream_name = "S3Delivery"
    }

    compression_format = "UNCOMPRESSED"

    processing_configuration {
      enabled = "false"
    }

    role_arn       = "arn:aws:iam::641885301384:role/service-role/KinesisFirehoseServiceRole-acqa-test--ca-central-1-1603971996403"
    s3_backup_mode = "Disabled"
  }

  name = "acqa-test-kinesisfirehoseds1"

  server_side_encryption {
    enabled  = "false"
    # key_type = "AWS_OWNED_CMK"
  }

  tags = {
    ACQAResource = "true"
    Name         = format("%s-kinesisfirehoseds1", var.acqaPrefix)
    Owner        = "AC-QA"
  }
}


# NACL
resource "aws_network_acl" "acqa-test-nacl1" {
  vpc_id = aws_vpc.acqa-test-vpc1.id

  egress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "10.3.0.0/18"
    from_port  = 443
    to_port    = 443
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.3.0.0/18"
    from_port  = 80
    to_port    = 80
  }

  tags = {
    ACQAResource = "true"
    Name         = format("%s-nacl1", var.acqaPrefix)
    Owner        = "AC-QA"
  }
}

# NAT Gateway
# resource "aws_nat_gateway" "acqa-test-natgateway1" {
#   allocation_id = aws_eip.acqa-test-eip1.id
#   subnet_id     = aws_subnet.acqa-test-subnet1.id

#   tags = {
#     ACQAResource = "true"
#     Name         = format("%s-natgateway1", var.acqaPrefix)
#     Owner        = "AC-QA"
#   }
# }

# Route Table
resource "aws_route_table" "acqa-test-routetable1" {
  vpc_id = aws_vpc.acqa-test-vpc1.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.acqa-test-gateway1.id
  }

  tags = {
    ACQAResource = "true"
    Name         = format("%s-routetable1", var.acqaPrefix)
    Owner        = "AC-QA"
  }
}

resource "aws_flow_log" "acqa-test-vpc1-flowlog1" {
  iam_role_arn    = aws_iam_role.acqa-test-flowlog-role1.arn
  log_destination = aws_cloudwatch_log_group.acqa-test-cwlg2.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.acqa-test-vpc1.id

    tags = {
    ACQAResource = "true"
    Name         = format("%s-vpc1-flowlog1", var.acqaPrefix)
    Owner        = "AC-QA"
  }
}

resource "aws_cloudwatch_log_group" "acqa-test-cwlg2" {
  name = "acqa-test-cwlg2"
  tags = {
    ACQAResource = "true"
    Name         = format("%s-cwlg2", var.acqaPrefix)
    Owner        = "AC-QA"
  }
}

resource "aws_iam_role" "acqa-test-flowlog-role1" {
  name = "acqa-test-flowlog-role1"
  tags = {
      ACQAResource = "true"
      Name         = format("%s-flowlog-role1", var.acqaPrefix)
      Owner        = "AC-QA"
    }
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "acqa-test-flowlog-rolepolicy1" {
  name = "acqa-test-flowlog-rolepolicy1"
  role = aws_iam_role.acqa-test-flowlog-role1.id

  policy = <<EOF
{
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}
EOF
}
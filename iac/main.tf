# The main provider block specifies the cloud platform and region
provider "aws" {
  region = var.aws_region
}

# Define the region variable
variable "aws_region" {
  description = "The AWS region where resources will be deployed."
  default     = "us-east-1" # Start with a standard region
}

# Define the environment tag for easy management
variable "environment" {
  description = "The deployment environment (e.g., dev, prod, mvp)"
  default     = "mvp"
}

# DynamoDB Table for Identity Exposure Index (I.E.I.) Scores
resource "aws_dynamodb_table" "identity_exposure_metrics" {
  name             = "IdentityExposureMetrics-${var.environment}"
  billing_mode     = "PAY_PER_REQUEST" # Cost-effective for an MVP
  hash_key         = "arn"

  attribute {
    name = "arn" # Partition key: The unique AWS ARN of the IAM Role
    type = "S"
  }

  tags = {
    Name        = "IEI Metrics Table"
    Environment = var.environment
  }
}

# Neptune Cluster for the Identity Graph (Central to the architecture)
resource "aws_neptune_cluster" "identity_graph_cluster" {
  cluster_identifier  = "identity-graph-cluster-${var.environment}"
  engine              = "neptune"
  backup_retention_period = 1
  skip_final_snapshot = true # Allows faster deletion during development

  # Note: A VPC is required for Neptune. We will assume a default VPC for now,
  # but in a later sprint (S4), we must define a dedicated, secure VPC.

  tags = {
    Name        = "IEI Neptune Graph"
    Environment = var.environment
  }
}

# Single Neptune Instance for the MVP (for cost control)
resource "aws_neptune_cluster_instance" "identity_graph_instance" {
  identifier        = "identity-graph-instance-1-${var.environment}"
  cluster_identifier = aws_neptune_cluster.identity_graph_cluster.id
  instance_class    = "db.t4g.medium" # Cost-effective instance type
  engine            = "neptune"
}

# 1. IAM Policy: Grants permission to assume roles and write logs
resource "aws_iam_policy" "collector_policy" {
  name        = "iei-collector-policy-${var.environment}"
  description = "Grants STS AssumeRole and CloudWatch logging permissions."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Required for logging
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
        Effect   = "Allow"
      },
      # CRITICAL: Permission to assume ANY role (we restrict this later)
      {
        Action   = "sts:AssumeRole"
        Resource = "*" # Allows assuming any role ARN passed to it
        Effect   = "Allow"
      }
    ]
  })
}

# 2. IAM Role: Assumed by the Lambda function
resource "aws_iam_role" "collector_role" {
  name               = "iei-collector-role-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
  tags = {
    Name = "IEI Collector Role"
  }
}

# 3. Attach the policy to the role
resource "aws_iam_role_policy_attachment" "collector_policy_attach" {
  role       = aws_iam_role.collector_role.name
  policy_arn = aws_iam_policy.collector_policy.arn
}

# 1. Package the Python code into a deployable zip file
data "archive_file" "collector_zip" {
  type        = "zip"
  # Change source_file to source_dir and include the requirements file
  source_dir  = "lambda/collector" 
  output_path = "lambda/collector/collector_handler.zip"
  
  # CRITICAL: This line makes sure Python packages are included
  # We will rely on a local install for the moment.
  # For full deployment, we would build a Lambda layer or use Docker.
  # For now, we package our utility folder and the handler:
  excludes    = ["test_collector.py"] # Exclude test files
}

# 2. Define the Lambda Function
resource "aws_lambda_function" "collector_lambda" {
  filename         = data.archive_file.collector_zip.output_path
  function_name    = "IEICollectorHandler-${var.environment}"
  role             = aws_iam_role.collector_role.arn
  handler          = "collector_handler.handler" # file.function
  source_code_hash = data.archive_file.collector_zip.output_base64sha256
  runtime          = "python3.12"
  timeout          = 30 # 30 seconds should be sufficient for API calls
  
  tags = {
    Name = "IEI Collector Function"
  }
}
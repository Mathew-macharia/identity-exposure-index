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
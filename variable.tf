variable "vpc_id" {
  default = ""
}

variable "private_subnets_ids" {
  default = ""
}
variable "cidr_block" {
  default = ""
}
variable "vpc_prefix_list_id" {
  type = string
}

variable "tenant_id" {
  type        =  string
    description = "select the region"
}
variable "region" {
  type        =  string
   description = "select the region"
}
variable "aws_elasticsearch" {
  type = map(object({
    name = string
  elasticsearch_version = string
  advanced_options = map(string)
  ebs_volume_size = number
  ebs_volume_type = string
  encrypt_at_rest_enabled =bool
  encrypt_at_rest_kms_key_id = string
  instance_count = number
instance_type = string
availability_zone_count = number
dedicated_master_enabled = bool
dedicated_master_count = number
dedicated_master_type = string
zone_awareness_enabled = bool
availability_zone_count = number
domain_endpoint_options_enforce_https = bool
domain_endpoint_options_tls_security_policy = string
custom_endpoint_enabled = bool
custom_endpoint = string
custom_endpoint_certificate_arn = string
cognito_authentication_enabled = bool
cognito_user_pool_id = string
cognito_identity_pool_id = string
cognito_iam_role_arn = string
automated_snapshot_start_hour = number
node_to_node_encryption_enabled = bool
}))
}
variable "create_iam_service_linked_role" {
  type        = bool
  default     = true
  description = "Whether to create `AWSServiceRoleForAmazonElasticsearchService` service-linked role. Set it to `false` if you already have an ElasticSearch cluster created in the AWS account and AWSServiceRoleForAmazonElasticsearchService already exists. See https://github.com/terraform-providers/terraform-provider-aws/issues/5218 for more info"
}

variable "node_to_node_encryption_enabled" {
  type        = bool
  default     = false
  description = "Whether to enable node-to-node encryption"
}

# variables for IAM policy

variable "iam_role_arns" {
  type        = list(string)
  default     = []
  description = "List of IAM role ARNs to permit access to the Elasticsearch domain"
}

variable "iam_role_permissions_boundary" {
  type        = string
  default     = null
  description = "The ARN of the permissions boundary policy which will be attached to the Elasticsearch user role"
}

variable "iam_authorizing_role_arns" {
  type        = list(string)
  default     = []
  description = "List of IAM role ARNs to permit to assume the Elasticsearch user role"
}

variable "iam_actions" {
  type        = list(string)
  default     = []
  description = "List of actions to allow for the IAM roles, _e.g._ `es:ESHttpGet`, `es:ESHttpPut`, `es:ESHttpPost`"
}


/* variable "domain_endpoint_options_enforce_https" {
  type        = bool
  default     = true
  description = "Whether or not to require HTTPS"
}

variable "domain_endpoint_options_tls_security_policy" {
  type        = string
  default     = "Policy-Min-TLS-1-0-2019-07"
  description = "The name of the TLS security policy that needs to be applied to the HTTPS endpoint"
}
variable "custom_endpoint_enabled" {
  type        = bool
  description = "Whether to enable custom endpoint for the Elasticsearch domain."
  default     = false
}

variable "custom_endpoint" {
  type        = string
  description = "Fully qualified domain for custom endpoint."
  default     = ""
}

variable "custom_endpoint_certificate_arn" {
  type        = string
  description = "ACM certificate ARN for custom endpoint."
  default     = ""
}
variable "cognito_authentication_enabled" {
  type        = bool
  default     = false
  description = "Whether to enable Amazon Cognito authentication with Kibana"
}

variable "cognito_user_pool_id" {
  type        = string
  default     = ""
  description = "The ID of the Cognito User Pool to use"
}

variable "cognito_identity_pool_id" {
  type        = string
  default     = ""
  description = "The ID of the Cognito Identity Pool to use"
}

variable "cognito_iam_role_arn" {
  type        = string
  default     = ""
  description = "ARN of the IAM role that has the AmazonESCognitoAccess policy attached"
}
variable "aws_ec2_service_name" {
  type        = list(string)
  default     = ["ec2.amazonaws.com"]
  description = "AWS EC2 Service Name"
}

variable "domain_hostname_enabled" {
  type        = bool
  description = "Explicit flag to enable creating a DNS hostname for ES. If `true`, then `var.dns_zone_id` is required."
  default     = false
}

variable "kibana_subdomain_name" {
  type        = string
  default     = ""
  description = "The name of the subdomain for Kibana in the DNS zone (_e.g._ `kibana`, `ui`, `ui-es`, `search-ui`, `kibana.elasticsearch`)"
}
variable "kibana_hostname_enabled" {
  type        = bool
  description = "Explicit flag to enable creating a DNS hostname for Kibana. If `true`, then `var.dns_zone_id` is required."
  default     = false
}

variable "advanced_security_options_enabled" {
  type        = bool
  default     = false
  description = "AWS Elasticsearch Kibana enchanced security plugin enabling (forces new resource)"
}

variable "advanced_security_options_internal_user_database_enabled" {
  type        = bool
  default     = false
  description = "Whether to enable or not internal Kibana user database for ELK OpenDistro security plugin"
}

variable "advanced_security_options_master_user_arn" {
  type        = string
  default     = ""
  description = "ARN of IAM user who is to be mapped to be Kibana master user (applicable if advanced_security_options_internal_user_database_enabled set to false)"
}

variable "advanced_security_options_master_user_name" {
  type        = string
  default     = ""
  description = "Master user username (applicable if advanced_security_options_internal_user_database_enabled set to true)"
}

variable "advanced_security_options_master_user_password" {
  type        = string
  default     = ""
  description = "Master user password (applicable if advanced_security_options_internal_user_database_enabled set to true)"
}

*/

region = "ap-southeast-1"
tenant_id = "jana"
vpc_id = "vpc-0f089c4d0e81093af"
private_subnets_ids = [ "subnet-00de6a7986fe8b141"
]
cidr_block = "10.0.0.0/24"
vpc_prefix_list_id = "pl-0e2034c85e48fbe71"
aws_elasticsearch = {
  "b2b-es" = {
    advanced_options = {
          }
          name = "jana"
    availability_zone_count = 2
    ebs_volume_size = 10
    ebs_volume_type = "gp2"
    elasticsearch_version = "7.4"
    encrypt_at_rest_enabled = true
    instance_count = 1
    instance_type = "r5.large.elasticsearch"
   
automated_snapshot_start_hour = 23
dedicated_master_enabled = false
dedicated_master_count = 0
dedicated_master_type = "t2.small.elasticsearch"
zone_awareness_enabled = false
automated_snapshot_start_hour = "23"
encrypt_at_rest_kms_key_id = ""
domain_endpoint_options_enforce_https = false
domain_endpoint_options_tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
custom_endpoint_enabled = false
custom_endpoint = ""
custom_endpoint_certificate_arn = ""
cognito_authentication_enabled = true
node_to_node_encryption_enabled = true

  }
}

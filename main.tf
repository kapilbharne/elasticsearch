provider "aws" {
  access_key = "AKIAWGQACST6YU35GQO6"
  secret_key = "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"
  region = var.region

}
data "aws_region" "current" {

}

resource "aws_security_group" "elastic-search-sg" {
  for_each    = var.aws_elasticsearch
  name        = "${var.tenant_id}-${each.value.name}-sg"
  description = "Managed by Terraform"
  vpc_id      = var.vpc_id
 /* tags = merge(each.value.tags, {
    Name   = "${var.tenant_id}-${each.value.name}-sg"
    Region = data.aws_region.current.name
  })*/
}

resource "aws_security_group_rule" "ES_out_all" {
  for_each          = var.aws_elasticsearch
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = -1
  prefix_list_ids   = [var.vpc_prefix_list_id]
  security_group_id = aws_security_group.elastic-search-sg[each.key].id
}

resource "aws_security_group_rule" "ES_http_all" {
  for_each          = var.aws_elasticsearch
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.elastic-search-sg[each.key].id
}

resource "aws_security_group_rule" "ES_https_all" {
  for_each          = var.aws_elasticsearch
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.elastic-search-sg[each.key].id
}

resource "aws_elasticsearch_domain" "default" {
  for_each              = var.aws_elasticsearch
  domain_name           = "${var.tenant_id}-${each.key}-domain"
  elasticsearch_version = each.value["elasticsearch_version"]

  advanced_options = each.value["advanced_options"]

  ebs_options {
    ebs_enabled = each.value["ebs_volume_size"] > 0 ? true : false
    volume_size = each.value["ebs_volume_size"]
    volume_type = each.value["ebs_volume_type"]
    # iops        = each.value["ebs_iops"]
  }
  encrypt_at_rest {
    enabled    = each.value["encrypt_at_rest_enabled"]
    kms_key_id = each.value["encrypt_at_rest_kms_key_id"]
  }
  cluster_config {
    instance_count           = each.value["instance_count"]
    instance_type            = each.value["instance_type"]
    dedicated_master_enabled = each.value["dedicated_master_enabled"]
    dedicated_master_count   = each.value["dedicated_master_count"]
    dedicated_master_type    = each.value["dedicated_master_type"]
    zone_awareness_enabled   = each.value["zone_awareness_enabled"]

    zone_awareness_config {
      availability_zone_count = each.value["availability_zone_count"]
    }
  }
  node_to_node_encryption {
    enabled = each.value["node_to_node_encryption_enabled"]  
    }
  snapshot_options {
    automated_snapshot_start_hour = each.value["automated_snapshot_start_hour"]
  }
  vpc_options {
    subnet_ids = var.private_subnets_ids
    security_group_ids = [
      aws_security_group.elastic-search-sg[each.key].id
    ]
  }
  domain_endpoint_options {
    enforce_https                   = each.value["domain_endpoint_options_enforce_https"]
    tls_security_policy             = each.value["domain_endpoint_options_tls_security_policy"]
    custom_endpoint_enabled         = each.value["custom_endpoint_enabled"]
    custom_endpoint                 = each.value["custom_endpoint_enabled"] ? each.value["custom_endpoint"] : null
    custom_endpoint_certificate_arn = each.value["custom_endpoint_enabled"] ? each.value["custom_endpoint_certificate_arn"] : null
  }
  cognito_options {
     enabled = each.value["cognito_authentication_enabled"]
      user_pool_id     = aws_cognito_user_pool.userpool[each.key].id
      identity_pool_id = aws_cognito_identity_pool.main[each.key].id
      role_arn         = aws_iam_role.authenticated[each.key].arn
    }
  }
  resource "aws_elasticsearch_domain_policy" "main" {
  for_each        = var.aws_elasticsearch
  domain_name     = aws_elasticsearch_domain.default[each.key].domain_name
  access_policies = <<POLICIES
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "es:*",
            "Principal": "*",
            "Effect": "Allow",
            "Resource": "${aws_elasticsearch_domain.default[each.key].arn}/*"
        }
           
    ]
}
POLICIES

}

# cognito configuration 

resource "aws_cognito_user_pool" "userpool" {
  for_each              = var.aws_elasticsearch
  name              = "${var.tenant_id}-${each.value.name}-userpool"
  mfa_configuration = "OFF"

  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
  }

  username_configuration {
    case_sensitive = false
  }

  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_numbers   = true
    require_uppercase = true
    require_symbols   = true
    temporary_password_validity_days  = 7
  }

  admin_create_user_config {
    allow_admin_create_user_only = false
      }

}

resource "aws_cognito_user_pool_client" "client" {
   for_each              = var.aws_elasticsearch
  name                                 = "${var.tenant_id}-${each.value.name}-client"
  user_pool_id                         = aws_cognito_user_pool.userpool[each.key].id
  
}

resource "aws_cognito_user_pool_domain" "domain" {
   for_each              = var.aws_elasticsearch
  domain       = "${var.tenant_id}-${each.value.name}"
  user_pool_id = aws_cognito_user_pool.userpool[each.key].id
}

resource "aws_cognito_identity_pool" "main" {
   for_each              = var.aws_elasticsearch
  identity_pool_name               = "${var.tenant_id}-${each.value.name}-identity-pool"
  allow_unauthenticated_identities = false
  allow_classic_flow               = false

  cognito_identity_providers {
    client_id               = aws_cognito_user_pool_client.client[each.key].id
    provider_name           = "cognito-idp.us-east-1.amazonaws.com/us-east-1_Tv0493apJ"
    server_side_token_check = false
   
    
  }
}

resource "aws_iam_role" "authenticated" {
   for_each              = var.aws_elasticsearch
  name = "${var.tenant_id}-${each.value.name}-cognito-role"
  
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.main [each.key].id}"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "authenticated"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "authenticated" {
   for_each              = var.aws_elasticsearch
    name = "${var.tenant_id}-${each.value.name}-authenticated_policy"
  role = aws_iam_role.authenticated[each.key].id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "mobileanalytics:PutEvents",
        "cognito-sync:*",
        "cognito-identity:*"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
EOF
}

resource "aws_cognito_identity_pool_roles_attachment" "main" {
   for_each              = var.aws_elasticsearch
  identity_pool_id = aws_cognito_identity_pool.main[each.key].id

  roles = {
    "authenticated" = aws_iam_role.authenticated[each.key].arn
  }

     }

  



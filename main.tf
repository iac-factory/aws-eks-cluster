################################################################################
# Main
################################################################################

resource "aws_eks_cluster" "cluster" {
    name                      = lower(format("%s", var.cluster_name))
    version                   = var.cluster_version
    enabled_cluster_log_types = var.cluster_log_types

    role_arn = aws_iam_role.cluster-iam-role.arn

    access_config {
        authentication_mode                         = "API_AND_CONFIG_MAP"
        bootstrap_cluster_creator_admin_permissions = false
    }

    vpc_config {
        security_group_ids = [
            aws_security_group.cluster.id
        ]

        subnet_ids              = var.cluster_private_subnet_ids
        endpoint_private_access = true
        endpoint_public_access  = false
    }

    kubernetes_network_config {
        ip_family = "ipv4"
    }

    timeouts {
        create = lookup(var.cluster_timeouts, "create", null)
        update = lookup(var.cluster_timeouts, "update", null)
        delete = lookup(var.cluster_timeouts, "delete", null)
    }

    depends_on = [
        aws_iam_role_policy_attachment.cluster-iam-policy-attachment,
        aws_security_group_rule.cluster-group-rule-outbound,
        aws_security_group_rule.cluster-group-rule,
    ]

    tags = merge({
        Name = lower(format("%s", var.cluster_name))
    }, local.tags)
}

resource "aws_eks_addon" "addon" {
    for_each = data.aws_eks_addon_version.addon

    addon_name    = each.value.addon_name
    cluster_name  = aws_eks_cluster.cluster.name
    addon_version = each.value.version

    resolve_conflicts_on_create = "OVERWRITE"
    resolve_conflicts_on_update = "OVERWRITE"

    depends_on = [aws_eks_node_group.node-group]

    tags = merge({
        Name        = format("%s", each.value.addon_name)
        Version     = format("%s", each.value.version)
        K8s-Version = format("%s", each.value.kubernetes_version)
    }, local.tags)
}

################################################################################
# Cluster Security Group
# Defaults follow https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html
################################################################################

resource "aws_security_group" "cluster" {
    name_prefix = lower(format("%s-cluster-sg-", var.cluster_name))
    vpc_id      = data.aws_vpc.vpc.id
    description = "Cluster Control-Plane API Security-Group"

    lifecycle {
        create_before_destroy = true
    }

    tags = merge({
        Name = lower(format("%s-cluster-sg", var.cluster_name))
    }, local.tags)
}

resource "aws_security_group_rule" "cluster-group-rule" {
    security_group_id = aws_security_group.cluster.id

    description = "Node Groups to Cluster API"
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    type        = "ingress"

    self = true
}

resource "aws_security_group_rule" "cluster-group-rule-outbound" {
    security_group_id = aws_security_group.cluster.id

    description = "Cluster API Outbound Access"
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    type        = "egress"

    cidr_blocks = ["0.0.0.0/0"]
}

# resource "aws_security_group_rule" "cluster-bastion-rule" {
#     security_group_id = aws_security_group.cluster.id
#
#     description = "Bastion to Cluster API"
#     protocol    = "tcp"
#     from_port   = 443
#     to_port     = 443
#     type        = "ingress"
#
#     source_security_group_id = module.bastion.bastion-security-group-id
# }

#resource "aws_security_group_rule" "cluster-bastion-rule" {
#    security_group_id = aws_security_group.cluster.id
#
#    description                = "Node Groups to Cluster API"
#    protocol                   = "tcp"
#    from_port                  = 443
#    to_port                    = 443
#    type                       = "ingress"
#
#    self = true
#}

################################################################################
# Node Security Group
# Defaults follow https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html
# Plus NTP/HTTPS (otherwise nodes fail to launch)
################################################################################

resource "aws_security_group" "node" {
    name_prefix = format("%s-node-sg-", var.cluster_name)
    description = "Cluster Node-Group Security-Group"
    vpc_id      = data.aws_vpc.vpc.id

    lifecycle {
        create_before_destroy = true
    }

    tags = merge({
        Name = lower(format("%s-node-sg", var.cluster_name))
    }, local.tags)
}

resource "aws_security_group_rule" "node-rule" {
    for_each = {
        for k, v in merge(
            local.node-security-group-rules,
            local.recommended-node-security-group-rules,
        ) : k => v
    }

    # Required
    security_group_id = aws_security_group.node.id
    protocol          = each.value.protocol
    from_port         = each.value.from_port
    to_port           = each.value.to_port
    type = each.value.type

    # Optional
    description      = lookup(each.value, "description", null)
    cidr_blocks      = lookup(each.value, "cidr_blocks", null)
    ipv6_cidr_blocks = lookup(each.value, "ipv6_cidr_blocks", null)
    prefix_list_ids  = lookup(each.value, "prefix_list_ids", [])
    self             = lookup(each.value, "self", null)

    source_security_group_id = try(each.value.source, false) ? aws_security_group.cluster.id : lookup(each.value, "source_security_group_id", null)
}


################################################################################
# IAM Role
################################################################################

resource "aws_iam_role" "cluster-iam-role" {
    name = lower(format("%s-cluster-role", var.cluster_name))
    path = format("%s", "/")

    description = format("Cluster IAM Role - %s", var.cluster_name)

    assume_role_policy    = data.aws_iam_policy_document.cluster-eks-cluster-assume-role-policy.json
    force_detach_policies = true

    # https://github.com/terraform-aws-modules/terraform-aws-eks/issues/920
    # Resources running on the cluster are still generating logs when destroying the module resources
    # which results in the log group being re-created even after Terraform destroys it. Removing the
    # ability for the cluster role to create the log group prevents this log group from being re-created
    # outside of Terraform due to services still generating logs during destroy process
    inline_policy {
        name = lower(format("%s-cluster-role", var.cluster_name))

        policy = jsonencode({
            Version   = "2012-10-17"
            Statement = [
                {
                    Action   = ["logs:CreateLogGroup"]
                    Effect   = "Deny"
                    Resource = "*"
                },
            ]
        })
    }

    tags = merge({
        Name = lower(format("%s-cluster-role", var.cluster_name))
    }, local.tags)
}

# Policies attached ref https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html
resource "aws_iam_role_policy_attachment" "cluster-iam-policy-attachment" {
    for_each = {
        for k, v in {
            EKS-Cluster-Policy          = "${local.cluster-iam-policy-prefix}/AmazonEKSClusterPolicy",
            EKS-VPC-Resource-Controller = "${local.cluster-iam-policy-prefix}/AmazonEKSVPCResourceController",
        } : k => v
    }

    policy_arn = each.value
    role       = aws_iam_role.cluster-iam-role.name
}

# Node Group

# role - https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html
resource "aws_iam_role" "node-group-role" {
    name        = lower(format("%s-node-group-role", var.cluster_name))
    description = "Node-Group IAM Role"
    path = format("%s", "/")

    force_detach_policies = true

    assume_role_policy = data.aws_iam_policy_document.cluster-eks-node-group-assume-role-policy.json

    tags = merge({
        Name = lower(format("%s-node-group-role", var.cluster_name))
    }, local.tags)
}

resource "aws_iam_policy" "node-group-aws-load-balancer-controller-policy" {
    name   = lower(format("%s-node-group-lb-controller-policy", var.cluster_name))
    policy = local.aws-loadbalancer-controller-iam-policy

    tags = merge({
        Name = lower(format("%s-node-group-lb-controller-policy", var.cluster_name))
    }, local.tags)
}

resource "aws_iam_role_policy_attachment" "node-group-role-aws-load-balancer-controller-policy" {
    policy_arn = aws_iam_policy.node-group-aws-load-balancer-controller-policy.arn
    role       = aws_iam_role.node-group-role.name
}

resource "aws_iam_role_policy_attachment" "node-group-role-eks-worker-policy" {
    policy_arn = data.aws_iam_policy.node-group-role-eks-worker-policy.arn
    role       = aws_iam_role.node-group-role.name
}

resource "aws_iam_role_policy_attachment" "node-group-role-cni-policy" {
    policy_arn = data.aws_iam_policy.node-group-role-cni-policy.arn
    role       = aws_iam_role.node-group-role.name
}

resource "aws_iam_role_policy_attachment" "node-group-role-ecr-registry-policy" {
    policy_arn = data.aws_iam_policy.node-group-role-ecr-registry-policy.arn
    role       = aws_iam_role.node-group-role.name
}

resource "aws_iam_role_policy_attachment" "node-group-role-ssm-policy" {
    policy_arn = data.aws_iam_policy.node-group-role-ssm-policy.arn
    role       = aws_iam_role.node-group-role.name
}

resource "aws_iam_role_policy_attachment" "node-group-role-efs-policy" {
    policy_arn = data.aws_iam_policy.node-group-role-efs-policy.arn
    role       = aws_iam_role.node-group-role.name
}

resource "aws_iam_role_policy_attachment" "node-group-role-ebs-policy" {
    policy_arn = data.aws_iam_policy.node-group-role-ebs-policy.arn
    role       = aws_iam_role.node-group-role.name
}

resource "aws_eks_node_group" "node-group" {
    cluster_name  = aws_eks_cluster.cluster.name
    node_role_arn = aws_iam_role.node-group-role.arn
    subnet_ids    = var.cluster_private_subnet_ids

    node_group_name        = null
    node_group_name_prefix = lower(format("%s-node-group-", var.cluster_name))

    version         = aws_eks_cluster.cluster.version
    release_version = nonsensitive(data.aws_ssm_parameter.eks-ami-release-version.value)
    ami_type        = "AL2_ARM_64"
    disk_size       = 20
    instance_types  = [
        "t4g.small"
    ]

    scaling_config {
        desired_size = 5
        max_size     = 15
        min_size     = 5
    }

    update_config {
        max_unavailable = 3
    }

    # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
    # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
    depends_on = [
        aws_iam_role_policy_attachment.node-group-role-eks-worker-policy,
        aws_iam_role_policy_attachment.node-group-role-cni-policy,
        aws_iam_role_policy_attachment.node-group-role-ecr-registry-policy,
        aws_iam_role_policy_attachment.node-group-role-ssm-policy,
        aws_iam_role_policy_attachment.node-group-role-efs-policy,
        aws_iam_role_policy_attachment.node-group-role-ebs-policy,
    ]

    tags = merge({
        Name = lower(format("%s-node-group-", var.cluster_name))
    }, local.tags)

    lifecycle {
        create_before_destroy = true
    }
}

resource "aws_iam_openid_connect_provider" "openid-provider" {
    client_id_list  = ["sts.amazonaws.com"]
    thumbprint_list = [
        data.tls_certificate.thumbprint.certificates[0].sha1_fingerprint
    ]
    url = data.tls_certificate.thumbprint.url
}

resource "aws_eks_identity_provider_config" "identity-provider-configuration" {
    cluster_name = aws_eks_cluster.cluster.name

    oidc {
        client_id                     = substr(aws_eks_cluster.cluster.identity[0].oidc[0]["issuer"], -32, -1)
        identity_provider_config_name = "identity-provider-configuration"
        issuer_url                    = "https://${aws_iam_openid_connect_provider.openid-provider.url}"
    }
}

resource "aws_iam_role" "cluster-service-account-role" {
    assume_role_policy = data.aws_iam_policy_document.service-account-iam-policy.json
    name               = lower(format("%s-service-account-role", var.cluster_name))

    tags = merge({
        Name = lower(format("%s-service-account-role", var.cluster_name))
    }, local.tags)
}

resource kubernetes_service_account "cluster-service-account" {
    metadata {
        name      = "cluster-service-account"
        namespace = "default" // @TODO standardize
        annotations = {
            "eks.amazonaws.com/role-arn" = aws_iam_role.cluster-service-account-role.arn
        }
    }
}

resource "helm_release" "aws-loadbalancer-controller" {
    chart      = "aws-load-balancer-controller"
    name       = "aws-load-balancer-controller"
    repository = "https://aws.github.io/eks-charts"
    namespace  = "kube-system"

    create_namespace = false

    atomic  = true
    wait    = true
    timeout = 900

    cleanup_on_fail = true

    dependency_update = true
    force_update      = true

    set {
        name  = "clusterName"
        value = aws_eks_cluster.cluster.name
    }

    set {
        name  = "logLevel"
        value = "debug"
    }
}

resource "helm_release" "metrics-server" {
    chart      = "metrics-server"
    name       = "metrics-server"
    repository = "https://kubernetes-sigs.github.io/metrics-server"
    namespace  = "kube-system"

    create_namespace = false

    atomic  = true
    wait    = true
    timeout = 900

    cleanup_on_fail = true

    dependency_update = true
    force_update      = true
}

resource "helm_release" "external-secrets" {
    chart      = "external-secrets"
    name       = "external-secrets"
    repository = "https://charts.external-secrets.io"
    namespace  = "external-secrets"

    create_namespace = true
    skip_crds        = false

    atomic  = true
    wait    = true
    timeout = 900

    cleanup_on_fail = true

    dependency_update = true
    force_update      = true
}

resource "helm_release" "prometheus" {
    name       = "kube-prometheus-stack"
    chart      = "kube-prometheus-stack"
    repository = "https://prometheus-community.github.io/helm-charts"
    namespace  = "prometheus"

    set {
        name  = "alertmanager.persistentVolume.storageClass"
        value = "gp3"
    }

    set {
        name  = "server.persistentVolume.storageClass"
        value = "gp3"
    }

    create_namespace = true
    skip_crds        = false

    atomic  = true
    wait    = true
    timeout = 900

    cleanup_on_fail = true

    dependency_update = true
    force_update      = true
}

resource "helm_release" "crossplane" {
   name  = "crossplane"
   chart = "crossplane"

   namespace = "crossplane-system"

   repository = "https://charts.crossplane.io/stable"

   create_namespace = true

   atomic  = true
   wait    = true
   timeout = 900

   cleanup_on_fail = true
}

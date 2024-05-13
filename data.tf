################################################################################
# Data
################################################################################

data "aws_partition" "arn" {}
data "aws_region" "region" {}
data "aws_caller_identity" "caller" {}

data "aws_subnet" "subnet" {
    for_each = local.subnets

    id = each.value
}

data "aws_vpc" "vpc" {
    id = data.aws_subnet.subnet[keys(local.subnets)[0]].vpc_id
}

data "aws_availability_zones" "available" {}

data "aws_ami" "ami" {
    most_recent = true
    owners      = ["amazon"]

    filter {
        name   = "name"
        values = ["al2023-ami-2023.*-kernel-*-x86_64"]
    }
}

data "aws_iam_policy_document" "cluster-eks-cluster-assume-role-policy" {
    statement {
        effect = "Allow"

        principals {
            type        = "Service"
            identifiers = ["eks.amazonaws.com"]
        }

        actions = ["sts:AssumeRole"]
    }
}

data "aws_iam_policy_document" "cluster-eks-node-group-assume-role-policy" {
    statement {
        effect = "Allow"

        principals {
            type        = "Service"
            identifiers = ["ec2.amazonaws.com"]
        }

        actions = ["sts:AssumeRole"]
    }
}

data "aws_eks_addon_version" "addon" {
    for_each = local.cluster-addons

    addon_name         = each.key
    kubernetes_version = aws_eks_cluster.cluster.version
    most_recent        = lookup(each.value, "latest", false)
}

# aws ssm get-parameters-by-path --path /aws/service/eks/
data "aws_ssm_parameter" "eks-ami-release-version" {
    name = "/aws/service/eks/optimized-ami/${aws_eks_cluster.cluster.version}/amazon-linux-2-arm64/recommended/release_version"
}

// !!! Required
data "aws_iam_policy" "node-group-role-eks-worker-policy" {
    arn = "arn:${data.aws_partition.arn.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

// !!! Required
data "aws_iam_policy" "node-group-role-cni-policy" {
    arn = "arn:${data.aws_partition.arn.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
}

// !!! Required
data "aws_iam_policy" "node-group-role-ecr-registry-policy" {
    arn = "arn:${data.aws_partition.arn.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

// !!! Optional
data "aws_iam_policy" "node-group-role-ssm-policy" {
    arn = "arn:${data.aws_partition.arn.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

// !!! Optional
data "aws_iam_policy" "node-group-role-efs-policy" {
    arn = "arn:${data.aws_partition.arn.partition}:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy"
}

// !!! Optional
data "aws_iam_policy" "node-group-role-ebs-policy" {
    arn = "arn:${data.aws_partition.arn.partition}:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

data "tls_certificate" "thumbprint" {
    url = aws_eks_cluster.cluster.identity[0].oidc[0]["issuer"]
}

data "aws_iam_policy_document" "service-account-iam-policy" {
    statement {
        actions = ["sts:AssumeRoleWithWebIdentity"]
        effect  = "Allow"

        condition {
            test     = "StringEquals"
            variable = "${replace(aws_iam_openid_connect_provider.openid-provider.url, "https://", "")}:sub"
            values   = ["system:serviceaccount:kube-system:aws-node"]
        }

        principals {
            identifiers = [aws_iam_openid_connect_provider.openid-provider.arn]
            type        = "Federated"
        }
    }
}

# terraform {
#     backend "http" {}
# }

provider "kubernetes" {
    host                   = aws_eks_cluster.cluster.endpoint
    cluster_ca_certificate = base64decode(aws_eks_cluster.cluster.certificate_authority[0].data)
    config_path = "~/.kube/config"

    exec {
        command     = "aws"
        api_version = "client.authentication.k8s.io/v1"
        args = [
            "eks", "update-kubeconfig", "--name", aws_eks_cluster.cluster.name
        ]
    }

    exec {
        command     = "aws"
        api_version = "client.authentication.k8s.io/v1"
        args = [
            "eks", "get-token", "--cluster-name", aws_eks_cluster.cluster.name
        ]
    }
}

provider "helm" {
    kubernetes {
        host = aws_eks_cluster.cluster.endpoint
        config_path = "~/.kube/config"
        cluster_ca_certificate = base64decode(aws_eks_cluster.cluster.certificate_authority[0].data)

        exec {
            command     = "aws"
            api_version = "client.authentication.k8s.io/v1"
            args = [
                "eks", "update-kubeconfig", "--name", aws_eks_cluster.cluster.name
            ]
        }

        exec {
            command     = "aws"
            api_version = "client.authentication.k8s.io/v1"
            args = [
                "eks", "get-token", "--cluster-name", aws_eks_cluster.cluster.name
            ]
        }
    }
}

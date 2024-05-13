output "cluster_id" {
    value = local.cluster-identifier
}

output "cluster_name" {
    value = aws_eks_cluster.cluster.name
}

output "cluster_identity_oidc_issuer" {
    value = aws_eks_cluster.cluster.identity[0].oidc[0]["issuer"]
}

output "cluster_identity_provider_urls" {
    value = {
        uri = aws_iam_openid_connect_provider.openid-provider.url
        url = "https://${aws_iam_openid_connect_provider.openid-provider.url}"
    }
}

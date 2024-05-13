locals {
    cluster-ipv4-cidr = "10.128.0.0/16"
    cluster-iam-policy-prefix = "arn:${data.aws_partition.arn.partition}:iam::aws:policy"

    cluster-identifier = split(".", trimprefix(aws_eks_cluster.cluster.endpoint, "https://"))[0]

    aws-loadbalancer-controller-iam-policy = file("iam-policy.json")
    cluster-node-group-aws-loadbalancer-controller-iam-policy = file("node-group-iam-policy.json")

    subnets = {for s in var.cluster_private_subnet_ids : s => lower(s)}

    tags = {
        TF = format("%s", "True")
        Cloud = format("%s", "AWS")
        Cluster = lower(format("%s", var.cluster_name))
    }

    node-security-group-rules = {
        ingress-cluster-control-plane-443 = {
            description = "Cluster API (Control Plane) to cluster node groups"
            protocol    = "tcp"
            from_port   = 443
            to_port     = 443
            type        = "ingress"
            source      = true
        }

        ingress-cluster-kubelet = {
            description = "Cluster API (Control Plane) to node kubelet(s)"
            protocol    = "tcp"
            from_port   = 10250
            to_port     = 10250
            type        = "ingress"
            source      = true
        }

        ingress-self-coredns-tcp = {
            description = "Node-to-Node CoreDNS, TCP"
            protocol    = "tcp"
            from_port   = 53
            to_port     = 53
            type        = "ingress"
            self        = true
        }

        ingress-self-coredns-udp = {
            description = "Node-to-Node CoreDNS, UDP"
            protocol    = "udp"
            from_port   = 53
            to_port     = 53
            type        = "ingress"
            self        = true
        }
    }

    recommended-node-security-group-rules = {
        ingress-self-ephemeral-ports = {
            description = "Node-to-Node ingress on ephemeral ports"
            protocol    = "tcp"
            from_port   = 1025
            to_port     = 65535
            type        = "ingress"
            self        = true
        }

        ingress-cluster-control-plane-webhook = {
            description = "Cluster-API-to-Node 4443/tcp webhook"
            protocol    = "tcp"
            from_port   = 4443
            to_port     = 4443
            type        = "ingress"
            source      = true
        }

        # prometheus-adapter
        ingress-cluster-prometheus-webhook = {
            description = "Cluster API to node 6443/tcp webhook"
            protocol    = "tcp"
            from_port   = 6443
            to_port     = 6443
            type        = "ingress"
            source      = true
        }

        # ALB controller, NGINX
        ingress-cluster-9443-webhook = {
            description = "Cluster API to node 9443/tcp webhook"
            protocol    = "tcp"
            from_port   = 9443
            to_port     = 9443
            type        = "ingress"
            source      = true
        }

        egress-all = {
            description = "Allow all egress"
            protocol    = "-1"
            from_port   = 0
            to_port     = 0
            type        = "egress"
            cidr_blocks = ["0.0.0.0/0"]
        }
    }

    cluster-addons = {
        // https://docs.aws.amazon.com/eks/latest/userguide/eks-add-ons.html
        kube-proxy = {
            latest = true
        }

        vpc-cni = {
            latest = true
        }

        coredns = {
            latest = true
        }

        aws-ebs-csi-driver = {
            latest  = true
        }

        eks-pod-identity-agent = {
            latest = true
        }

        // amazon-cloudwatch-observability = {
        //     latest  = true
        // }

        // snapshot-controller = {
        //     latest  = true
        // }

    }
}

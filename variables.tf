################################################################################
# Variables
################################################################################

variable "cluster_version" {
    description = "Kubernetes `<major>.<minor>` version to use for the EKS cluster (i.e.: `1.27`)"
    type        = string
    default     = "1.29"
}

variable "cluster_name" {
    description = "The Kubernetes cluster name."
    type = string
}

variable "cluster_log_types" {
    description = "A list of the desired control plane logs to enable. For more information, see Amazon [EKS Control Plane Logging documentation](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html)"
    type        = list(string)
    default     = ["audit", "api", "authenticator", "controllerManager", "scheduler"]
}

variable "cluster_additional_log_group_ids" {
    description = "List of additional, externally created security group IDs to attach to the cluster control plane"
    type        = list(string)
    default     = []
}

variable "cluster_timeouts" {
    description = "Create, update, and delete timeout configurations for the cluster"
    type        = object({
        create = optional(string)
        update = optional(string)
        delete = optional(string)
    })

    default     = {
        create = null
        update = null
        delete = null
    }
}

variable "cluster_private_subnet_ids" {
    description = "List of subnet identifiers for a private VPC."
    type = set(string)

    validation {
        condition = length(var.cluster_private_subnet_ids) >= 3
        error_message = "Must contain at least three total subnet identifiers."
    }
}

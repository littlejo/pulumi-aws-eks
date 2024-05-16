import pulumi
import pulumi_aws as aws
import helper as h

config = pulumi.Config()
azs = config.require_object("azs")
cp_role_name = config.require("controlPlaneRoleName")
np_role_name = config.require("nodePoolRoleName")
cp_sg_name = config.require("controlPlaneSecurityGroupName")
np_sg_name = config.require("nodePoolSecurityGroupName")

cp_name = config.require("controlPlaneName")
np_name = config.require("nodePoolName")

subnets = aws.ec2.get_subnets(
    filters=[
        aws.ec2.GetSubnetsFilterArgs(
            name="availability-zone",
            values=azs,
        )
    ]
)

# Create an AWS role for the EKS cluster.
eks_role = aws.iam.Role(
    "eksRole",
    name=cp_role_name,
    assume_role_policy=pulumi.Output.from_input(
        h.get_assume_role_policy_document("eks.amazonaws.com")
    ),
    managed_policy_arns=["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"],
)

# Create an AWS role for the ec2 cluster.
ec2_role = aws.iam.Role(
    "ec2Role",
    name=np_role_name,
    assume_role_policy=pulumi.Output.from_input(
        h.get_assume_role_policy_document("ec2.amazonaws.com")
    ),
    managed_policy_arns=[
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
        "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
        "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    ],
)

# Create an AWS SG for the EKS cluster.
eks_sg = aws.ec2.SecurityGroup("eks_sg", name=cp_sg_name, description="EKS control plane security group", tags={"Name": cp_sg_name})
eks_ingress_rules = [{"id": "ingress-eks", "proto": "tcp", "port": 443, "cidr_ipv4": "0.0.0.0/0"}]
eks_egress_rules = [{"id": "egress-eks", "proto": "-1", "cidr_ipv4": "0.0.0.0/0"}]

# Create an AWS SG for the ec2 cluster.
ec2_sg = aws.ec2.SecurityGroup("ec2_sg", name=np_sg_name, description="EKS nodes security group", tags={"Name": np_sg_name})
ec2_ingress_rules = [
  { "id": "ingress-ec2-https", "proto": "tcp", "port": 443, "dest_sg_id": eks_sg.id},
  { "id": "ingress-ec2-all", "proto": "-1", "dest_sg_id": ec2_sg.id, "description": "All access from nodepool"},
  { "id": "ingress-ec2-other", "proto": "tcp", "from_port": 1025, "to_port": 65535, "dest_sg_id": eks_sg.id},
]
ec2_egress_rules = [{"id": "egress-ec2", "proto": "-1", "cidr_ipv4": "0.0.0.0/0"}]

h.create_rules(eks_sg.id, eks_ingress_rules, eks_egress_rules)
h.create_rules(ec2_sg.id, ec2_ingress_rules, ec2_egress_rules)

## Create an EKS cluster.
eks_cluster = aws.eks.Cluster(
    "eksCluster",
    name=cp_name,
    role_arn=eks_role.arn,
    vpc_config=aws.eks.ClusterVpcConfigArgs(
        subnet_ids=subnets.ids,
        security_group_ids=[eks_sg.id],
        endpoint_private_access=True,
        endpoint_public_access=True,
        public_access_cidrs=["0.0.0.0/0"],
    ),
)

## Create an EKS NodeGroup
eks_np = aws.eks.NodeGroup("eksNodePool",
    cluster_name=eks_cluster.name,
    node_group_name=np_name,
    node_role_arn=ec2_role.arn,
    subnet_ids=subnets.ids,
    scaling_config=aws.eks.NodeGroupScalingConfigArgs(
        desired_size=1,
        max_size=2,
        min_size=1,
    ),
    update_config=aws.eks.NodeGroupUpdateConfigArgs(
        max_unavailable=1,
    ),
)

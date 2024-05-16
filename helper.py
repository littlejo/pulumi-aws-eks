import pulumi_aws as aws

def get_assume_role_policy_document(service):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Effect": "Allow",
                "Principal": {"Service": service},
            }
        ],
    }

def create_rules(sg_id, ingress_rules, egress_rules):
    for r in ingress_rules:
        if 'port' in r:
           r['from_port'] = r['port']
           r['to_port'] = r['port']
        if "enable" in r and not r["enable"]:
           continue
        aws.vpc.SecurityGroupIngressRule(
            r['id'],
            security_group_id=sg_id,
            ip_protocol=r['proto'],
            from_port=r.get('from_port', None),
            to_port=r.get('to_port', None),
            referenced_security_group_id=r.get('dest_sg_id', None),
            cidr_ipv4=r.get('cidr_ipv4', None),
            description=r.get('description', None),
        )

    for r in egress_rules:
        if 'port' in r:
           r['from_port'] = r['port']
           r['to_port'] = r['port']
        if "enable" in r and not r["enable"]:
           continue
        aws.vpc.SecurityGroupEgressRule(
            r['id'],
            security_group_id=sg_id,
            ip_protocol=r['proto'],
            from_port=r.get('from_port', None),
            to_port=r.get('to_port', None),
            referenced_security_group_id=r.get('dest_sg_id', None),
            cidr_ipv4=r.get('cidr_ipv4', None),
            description=r.get('description', None),
        )

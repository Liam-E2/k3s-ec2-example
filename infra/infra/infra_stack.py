from pathlib import Path

import aws_cdk as cdk
from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    Tags,
    CfnOutput,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_s3 as s3,
    aws_secretsmanager as sm,
    aws_autoscaling as autoscaling,
    aws_elasticloadbalancingv2 as elbv2,
    aws_ssm as ssm,
    aws_lambda as lambda_,
    aws_sqs as sqs,
    aws_events as events,
    aws_events_targets as targets,
    custom_resources as cr,
)
from aws_cdk import CfnJson
from cdk_fck_nat import FckNatInstanceProvider
from constructs import Construct

_KEYPAIR_HANDLER = (Path(__file__).parent / "handlers" / "keypair_handler.py").read_text()


class InfraStack(Stack):

    def __init__(self, scope: Construct, construct_id: str,
                 cluster_name, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.cluster_name = cluster_name 
        
        vpc = self._build_vpc(cluster_name)
        cp_sg, tailscale_sg = self._build_security_groups(vpc, cluster_name)
        cp_role, tailscale_role = self._build_iam_roles()
        cluster_token, sa_key_secret = self._build_secrets(cp_role, tailscale_role)
        oidc_bucket, issuer_url = self._build_oidc_bucket()
        nlb = self._build_nlb(vpc)

        oidc_provider = self._build_keypair_resource(sa_key_secret, oidc_bucket, issuer_url)

        self._build_worker_security_group(vpc, cp_sg, cluster_name)
        karpenter_role = self._build_karpenter_controller_role(oidc_provider, cluster_name)
        _, node_profile = self._build_karpenter_node_role(cluster_token)
        interruption_queue = self._build_karpenter_interruption_queue(cluster_name)
        eso_role = self._build_eso_role(oidc_provider, cluster_name)

        self._build_ssm_params(
            cp_role, cluster_name, nlb, issuer_url,
            cluster_token, karpenter_role, node_profile, interruption_queue, eso_role,
        )

        cp_asg = self._build_control_plane(
            vpc, cp_role, cp_sg, cluster_token, sa_key_secret, nlb, issuer_url, cluster_name)
        self._build_nlb_listeners(nlb, vpc, cp_asg)
        self._build_tailscale(vpc, tailscale_role, tailscale_sg)

        self._build_outputs(nlb, issuer_url, cluster_token, karpenter_role, node_profile, interruption_queue)

    # ── VPC ──────────────────────────────────────────────────────────────────

    def _build_vpc(self, cluster_name: str) -> ec2.Vpc:
        fck_nat = FckNatInstanceProvider(instance_type=ec2.InstanceType("t4g.nano"))

        vpc = ec2.Vpc(self, "Vpc",
            max_azs=3,
            nat_gateways=1,
            nat_gateway_provider=fck_nat,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24,
                ),
            ],
        )

        fck_nat.security_group.add_ingress_rule(
            ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.all_traffic())

        for subnet in vpc.private_subnets:
            Tags.of(subnet).add("karpenter.sh/discovery", cluster_name)

        return vpc

    # ── Security Groups ───────────────────────────────────────────────────────

    def _build_security_groups(
        self, vpc: ec2.Vpc, cluster_name: str,
    ) -> tuple[ec2.SecurityGroup, ec2.SecurityGroup]:
        cp_sg = ec2.SecurityGroup(self, "ControlPlaneSG",
            vpc=vpc,
            description="k3s control plane",
            allow_all_outbound=True,
        )
        cp_sg.add_ingress_rule(
            ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(6443), "k3s API")
        cp_sg.add_ingress_rule(
            ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(9345), "k3s supervisor")
        cp_sg.add_ingress_rule(cp_sg, ec2.Port.tcp(2379), "etcd client")
        cp_sg.add_ingress_rule(cp_sg, ec2.Port.tcp(2380), "etcd peer")
        cp_sg.add_ingress_rule(cp_sg, ec2.Port.udp(8472), "flannel VXLAN")
        Tags.of(cp_sg).add("karpenter.sh/discovery", cluster_name)

        tailscale_sg = ec2.SecurityGroup(self, "TailscaleSG",
            vpc=vpc,
            description="Tailscale subnet router (outbound only)",
            allow_all_outbound=True,
        )

        return cp_sg, tailscale_sg

    def _build_worker_security_group(
        self,
        vpc: ec2.Vpc,
        cp_sg: ec2.SecurityGroup,
        cluster_name: str,
    ) -> ec2.SecurityGroup:
        worker_sg = ec2.SecurityGroup(self, "WorkerNodeSG",
            vpc=vpc,
            description="k3s worker nodes (Karpenter-launched)",
            allow_all_outbound=True,
        )
        Tags.of(worker_sg).add("karpenter.sh/discovery", cluster_name)

        # Workers need full connectivity to/from control plane (kubelet, CNI, flannel)
        worker_sg.add_ingress_rule(cp_sg, ec2.Port.all_traffic(), "Control plane to worker")
        worker_sg.add_ingress_rule(worker_sg, ec2.Port.all_traffic(), "Worker to worker")
        cp_sg.add_ingress_rule(worker_sg, ec2.Port.all_traffic(), "Worker to control plane")

        return worker_sg

    # ── IAM Roles ─────────────────────────────────────────────────────────────

    def _build_iam_roles(self) -> tuple[iam.Role, iam.Role]:
        ssm_core = iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")

        cp_role = iam.Role(self, "ControlPlaneRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[ssm_core],
        )
        tailscale_role = iam.Role(self, "TailscaleRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[ssm_core],
        )

        return cp_role, tailscale_role

    def _build_karpenter_controller_role(
        self,
        oidc_provider: iam.OpenIdConnectProvider,
        cluster_name: str,
    ) -> iam.Role:
        oidc_arn = oidc_provider.open_id_connect_provider_arn
        # open_id_connect_provider_issuer is a CloudFormation token (no https:// prefix).
        # CfnJson is required so CDK can resolve this token as a dict *key* at deploy time.
        oidc_issuer = oidc_provider.open_id_connect_provider_issuer
        oidc_conditions = CfnJson(self, "KarpenterOidcConditions", value={
            f"{oidc_issuer}:aud": "sts.amazonaws.com",
            f"{oidc_issuer}:sub": "system:serviceaccount:karpenter:karpenter",
        })

        controller_role = iam.Role(self, "KarpenterControllerRole",
            assumed_by=iam.FederatedPrincipal(
                federated=oidc_arn,
                conditions={"StringEquals": oidc_conditions},
                assume_role_action="sts:AssumeRoleWithWebIdentity",
            ),
            description="Karpenter controller IRSA role",
        )

        controller_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "ec2:RunInstances",
                "ec2:TerminateInstances",
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeInstanceTypeOfferings",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeImages",
                "ec2:DescribeSpotPriceHistory",
                "ec2:DescribeSpotInstanceRequests",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeLaunchTemplates",
                "ec2:CreateLaunchTemplate",
                "ec2:DeleteLaunchTemplate",
                "ec2:CreateFleet",
                "ec2:CreateTags",
                "ec2:DeleteTags",
            ],
            resources=["*"],
        ))

        controller_role.add_to_policy(iam.PolicyStatement(
            actions=["iam:PassRole"],
            resources=[f"arn:aws:iam::{self.account}:role/*"],
            conditions={"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}},
        ))
        controller_role.add_to_policy(iam.PolicyStatement(
            actions=["iam:GetInstanceProfile"],
            resources=["*"],
        ))

        controller_role.add_to_policy(iam.PolicyStatement(
            actions=["ssm:GetParameter"],
            resources=[f"arn:aws:ssm:{self.region}::parameter/aws/service/ami-amazon-linux-latest/*"],
        ))

        controller_role.add_to_policy(iam.PolicyStatement(
            actions=["pricing:GetProducts"],
            resources=["*"],
        ))

        queue_arn = self.format_arn(
            service="sqs",
            resource=f"karpenter-{cluster_name}",
        )
        controller_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "sqs:GetQueueUrl",
                "sqs:GetQueueAttributes",
                "sqs:ReceiveMessage",
                "sqs:DeleteMessage",
            ],
            resources=[queue_arn],
        ))

        return controller_role

    def _build_eso_role(
        self,
        oidc_provider: iam.OpenIdConnectProvider,
        cluster_name: str,
    ) -> iam.Role:
        oidc_arn = oidc_provider.open_id_connect_provider_arn
        oidc_issuer = oidc_provider.open_id_connect_provider_issuer
        oidc_conditions = CfnJson(self, "EsoOidcConditions", value={
            f"{oidc_issuer}:aud": "sts.amazonaws.com",
            f"{oidc_issuer}:sub": "system:serviceaccount:external-secrets:external-secrets",
        })

        eso_role = iam.Role(self, "EsoControllerRole",
            assumed_by=iam.FederatedPrincipal(
                federated=oidc_arn,
                conditions={"StringEquals": oidc_conditions},
                assume_role_action="sts:AssumeRoleWithWebIdentity",
            ),
            description="External Secrets Operator IRSA role",
        )

        eso_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "ssm:GetParameter",
                "ssm:GetParameters",
                "ssm:GetParametersByPath",
            ],
            resources=[
                f"arn:aws:ssm:{self.region}:{self.account}:parameter/{cluster_name}/*",
            ],
        ))

        return eso_role

    def _build_karpenter_node_role(
        self,
        cluster_token: sm.Secret,
    ) -> tuple[iam.Role, iam.CfnInstanceProfile]:
        node_role = iam.Role(self, "KarpenterNodeRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ContainerRegistryReadOnly"),
            ],
            description="IAM role for Karpenter-launched worker nodes",
        )
        cluster_token.grant_read(node_role)

        # Fixed name so EC2NodeClass can reference it without depending on a CDK token
        instance_profile = iam.CfnInstanceProfile(self, "KarpenterNodeInstanceProfile",
            roles=[node_role.role_name],
            instance_profile_name=f"KarpenterNodeProfile-{self.stack_name}",
        )

        return node_role, instance_profile

    # ── Secrets ───────────────────────────────────────────────────────────────

    def _build_secrets(
        self, cp_role: iam.Role, tailscale_role: iam.Role,
    ) -> tuple[sm.Secret, sm.Secret]:
        cluster_token = sm.Secret(self, "ClusterToken",
            description="k3s cluster join token",
            generate_secret_string=sm.SecretStringGenerator(
                exclude_punctuation=True,
                password_length=64,
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )
        cluster_token.grant_read(cp_role)

        sa_key_secret = sm.Secret(self, "SaSigningKey",
            description="k3s service account signing private key (PEM)",
            removal_policy=RemovalPolicy.DESTROY,
        )
        sa_key_secret.grant_read(cp_role)

        # Pre-created by user:
        #   aws secretsmanager create-secret \
        #     --name {cluster_name}/tailscale-auth-key \
        #     --secret-string "tskey-auth-..."
        tailscale_secret = sm.Secret.from_secret_name_v2(
            self, "TailscaleAuthKey", f"{self.cluster_name}/tailscale-auth-key")
        tailscale_secret.grant_read(tailscale_role)

        return cluster_token, sa_key_secret

    # ── OIDC S3 Bucket ────────────────────────────────────────────────────────

    def _build_oidc_bucket(self) -> tuple[s3.Bucket, str]:
        # publicAccessBlockedByDefault=true in cdk.json — must set all four False
        oidc_bucket = s3.Bucket(self, "OidcBucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess(
                block_public_acls=False,
                block_public_policy=False,
                ignore_public_acls=False,
                restrict_public_buckets=False,
            ),
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
        )
        oidc_bucket.add_to_resource_policy(iam.PolicyStatement(
            principals=[iam.AnyPrincipal()],
            actions=["s3:GetObject"],
            resources=[
                oidc_bucket.arn_for_objects("openid/*"),
                oidc_bucket.arn_for_objects(".well-known/*"),
            ],
        ))

        issuer_url = f"https://{oidc_bucket.bucket_domain_name}"
        return oidc_bucket, issuer_url

    # ── NLB ───────────────────────────────────────────────────────────────────

    def _build_nlb(self, vpc: ec2.Vpc) -> elbv2.NetworkLoadBalancer:
        nlb = elbv2.NetworkLoadBalancer(self, "ControlPlaneNLB",
            vpc=vpc,
            internet_facing=False,
            cross_zone_enabled=True,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
        )
        # NLB gets an auto SG (networkLoadBalancerWithSecurityGroupByDefault=true)
        nlb.connections.allow_from(
            ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(6443), "k3s API")
        nlb.connections.allow_from(
            ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(9345), "k3s supervisor")
        nlb.connections.allow_to(
            ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(6443), "k3s API")
        nlb.connections.allow_to(
            ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(9345), "k3s supervisor")

        return nlb

    # ── Custom Resource: RSA keypair + JWKS ───────────────────────────────────

    def _build_keypair_resource(
        self,
        sa_key_secret: sm.Secret,
        oidc_bucket: s3.Bucket,
        issuer_url: str,
    ) -> iam.OpenIdConnectProvider:
        keypair_fn = lambda_.Function(self, "KeypairFn",
            runtime=lambda_.Runtime.PYTHON_3_12,
            architecture=lambda_.Architecture.ARM_64,
            handler="index.handler",
            # Uses openssl CLI (available in AL2023 Lambda runtime) — no layer required.
            code=lambda_.Code.from_inline(_KEYPAIR_HANDLER),
            timeout=Duration.minutes(2),
        )
        sa_key_secret.grant_read(keypair_fn)
        sa_key_secret.grant_write(keypair_fn)
        oidc_bucket.grant_put(keypair_fn)

        provider = cr.Provider(self, "KeypairProvider", on_event_handler=keypair_fn)
        keypair_resource = cdk.CustomResource(self, "KeypairResource",
            service_token=provider.service_token,
            properties={
                "SecretArn": sa_key_secret.secret_arn,
                "BucketName": oidc_bucket.bucket_name,
                "IssuerUrl": issuer_url,
                "Region": self.region,
                "Nonce": "4",
            },
        )

        oidc_provider = iam.OpenIdConnectProvider(self, "OidcProvider",
            url=issuer_url,
            client_ids=["sts.amazonaws.com"],
            # SHA-1 thumbprint of Amazon Root CA 1 (root CA for S3 TLS)
            thumbprints=["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"],
        )
        oidc_provider.node.add_dependency(keypair_resource)

        return oidc_provider

    # ── Karpenter Interruption Queue ──────────────────────────────────────────

    def _build_karpenter_interruption_queue(self, cluster_name: str) -> sqs.Queue:
        queue = sqs.Queue(self, "KarpenterInterruptionQueue",
            queue_name=f"karpenter-{cluster_name}",
            retention_period=Duration.minutes(5),
        )
        queue.add_to_resource_policy(iam.PolicyStatement(
            principals=[
                iam.ServicePrincipal("events.amazonaws.com"),
                iam.ServicePrincipal("sqs.amazonaws.com"),
            ],
            actions=["sqs:SendMessage"],
            resources=[queue.queue_arn],
        ))

        def _rule(rule_id: str, source: list[str], detail_type: str) -> None:
            rule = events.Rule(self, rule_id,
                event_pattern=events.EventPattern(source=source, detail_type=[detail_type]),
            )
            rule.add_target(targets.SqsQueue(queue))

        _rule("SpotInterruptionRule",   ["aws.ec2"],    "EC2 Spot Instance Interruption Warning")
        _rule("RebalanceRule",          ["aws.ec2"],    "EC2 Instance Rebalance Recommendation")
        _rule("ScheduledChangeRule",    ["aws.health"], "AWS Health Event")
        _rule("InstanceStateChangeRule",["aws.ec2"],    "EC2 Instance State-change Notification")

        return queue

    # ── SSM Parameters ────────────────────────────────────────────────────────

    def _build_ssm_params(
        self,
        cp_role: iam.Role,
        cluster_name: str,
        nlb: elbv2.NetworkLoadBalancer,
        issuer_url: str,
        cluster_token: sm.Secret,
        karpenter_role: iam.Role,
        node_profile: iam.CfnInstanceProfile,
        interruption_queue: sqs.Queue,
        eso_role: iam.Role,
    ) -> None:
        ssm.StringParameter(self, "NlbDnsParam",
            parameter_name=f"/{cluster_name}/nlb-dns",
            string_value=nlb.load_balancer_dns_name,
        )
        ssm.StringParameter(self, "OidcIssuerParam",
            parameter_name=f"/{cluster_name}/oidc-issuer",
            string_value=issuer_url,
        )
        ssm.StringParameter(self, "ClusterTokenArnParam",
            parameter_name=f"/{cluster_name}/cluster-token-arn",
            string_value=cluster_token.secret_arn,
        )

        # Do NOT pre-create k3s-init-lock — the CAS relies on put-parameter --no-overwrite
        # succeeding only when the parameter doesn't exist yet.
        lock_param_arn = self.format_arn(
            service="ssm",
            resource="parameter",
            resource_name=f"{cluster_name}/k3s-init-lock",
        )

        init_ready_param = ssm.StringParameter(self, "InitReadyParam",
            parameter_name=f"/{cluster_name}/k3s-init-ready",
            string_value="false",
        )

        cp_role.add_to_policy(iam.PolicyStatement(
            actions=["ssm:PutParameter", "ssm:GetParameter"],
            resources=[lock_param_arn, init_ready_param.parameter_arn],
        ))

        ssm.StringParameter(self, "KarpenterControllerRoleArnParam",
            parameter_name=f"/{cluster_name}/karpenter/controller-role-arn",
            string_value=karpenter_role.role_arn,
        )
        ssm.StringParameter(self, "KarpenterNodeInstanceProfileParam",
            parameter_name=f"/{cluster_name}/karpenter/node-instance-profile",
            string_value=node_profile.ref,
        )
        ssm.StringParameter(self, "KarpenterInterruptionQueueParam",
            parameter_name=f"/{cluster_name}/karpenter/interruption-queue",
            string_value=interruption_queue.queue_name,
        )
        ssm.StringParameter(self, "EsoControllerRoleArnParam",
            parameter_name=f"/{cluster_name}/eso/controller-role-arn",
            string_value=eso_role.role_arn,
        )

    # ── Control Plane ─────────────────────────────────────────────────────────

    def _build_control_plane(
        self,
        vpc: ec2.Vpc,
        cp_role: iam.Role,
        cp_sg: ec2.SecurityGroup,
        cluster_token: sm.Secret,
        sa_key_secret: sm.Secret,
        nlb: elbv2.NetworkLoadBalancer,
        issuer_url: str,
        cluster_name: str,
    ) -> autoscaling.AutoScalingGroup:
        user_data = self._build_control_plane_user_data(
            cluster_token, sa_key_secret, nlb, issuer_url, cluster_name)

        launch_template = ec2.LaunchTemplate(self, "ControlPlaneLT",
            instance_type=ec2.InstanceType("t4g.small"),
            machine_image=ec2.MachineImage.latest_amazon_linux2023(
                cpu_type=ec2.AmazonLinuxCpuType.ARM_64),
            role=cp_role,
            security_group=cp_sg,
            user_data=user_data,
            require_imdsv2=True,
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/xvda",
                    volume=ec2.BlockDeviceVolume.ebs(
                        20,
                        volume_type=ec2.EbsDeviceVolumeType.GP3,
                        encrypted=True,
                    ),
                )
            ],
        )

        return autoscaling.AutoScalingGroup(self, "ControlPlaneASG",
            vpc=vpc,
            launch_template=launch_template,
            min_capacity=3,
            max_capacity=3,
            desired_capacity=3,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            update_policy=autoscaling.UpdatePolicy.rolling_update(),
        )

    def _build_control_plane_user_data(
        self,
        cluster_token: sm.Secret,
        sa_key_secret: sm.Secret,
        nlb: elbv2.NetworkLoadBalancer,
        issuer_url: str,
        cluster_name: str,
    ) -> ec2.UserData:
        ud = ec2.UserData.for_linux()
        ud.add_commands(
            "set -euo pipefail",
            f'REGION="{self.region}"',
            f'CLUSTER_NAME="{cluster_name}"',
            f'TOKEN_SECRET_ARN="{cluster_token.secret_arn}"',
            f'SA_KEY_SECRET_ARN="{sa_key_secret.secret_arn}"',
            f'NLB_DNS="{nlb.load_balancer_dns_name}"',
            f'ISSUER_URL="{issuer_url}"',
            f'LOCK_PARAM="/{cluster_name}/k3s-init-lock"',
            f'READY_PARAM="/{cluster_name}/k3s-init-ready"',
            "",
            "# IMDSv2 token",
            'IMDS_TOKEN=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token"'
            ' -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")',
            "",
            "# Fetch instance private IP",
            'MY_IP=$(curl -sf -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" '
            'http://169.254.169.254/latest/meta-data/local-ipv4)',
            "",
            "# Fetch cluster join token",
            'TOKEN=$(aws secretsmanager get-secret-value'
            ' --region "$REGION" --secret-id "$TOKEN_SECRET_ARN"'
            ' --query SecretString --output text)',
            "",
            "# Fetch SA signing key",
            "mkdir -p /etc/k3s",
            'aws secretsmanager get-secret-value'
            ' --region "$REGION" --secret-id "$SA_KEY_SECRET_ARN"'
            ' --query SecretString --output text > /etc/k3s/sa-signing.key',
            "chmod 600 /etc/k3s/sa-signing.key",
            "openssl rsa -in /etc/k3s/sa-signing.key -pubout -out /etc/k3s/sa-signing.pub",
            "",
            "# SSM compare-and-swap: first node wins cluster-init",
            'if aws ssm put-parameter --region "$REGION" --name "$LOCK_PARAM" '
            '--value "$MY_IP" --type String --no-overwrite 2>/dev/null; then',
            "    K3S_MODE='--cluster-init'",
            "else",
            "    # Read init node IP from SSM",
            '    INIT_NODE_IP=$(aws ssm get-parameter --region "$REGION" '
            ' --name "$LOCK_PARAM" --query Parameter.Value --output text)',
            "    # Wait for init node to finish bootstrapping",
            "    MAX_WAIT=300; ELAPSED=0",
            '    until [ "$(aws ssm get-parameter --region "$REGION"'
            ' --name "$READY_PARAM" --query Parameter.Value --output text 2>/dev/null)" = "true" ]; do',
            "        [ $ELAPSED -ge $MAX_WAIT ] && "
            '{ echo "Timed out waiting for init node" >&2; exit 1; }',
            "        sleep 10; ELAPSED=$((ELAPSED+10))",
            "    done",
            '    K3S_MODE="--server https://${INIT_NODE_IP}:6443"',
            "fi",
            "",
            "# Install k3s",
            'curl -sfL https://get.k3s.io | K3S_TOKEN="$TOKEN" sh -s - server \\',
            '    $K3S_MODE \\',
            '    --tls-san "$NLB_DNS" \\',
            '    --kube-apiserver-arg="service-account-issuer=${ISSUER_URL}" \\',
            '    --kube-apiserver-arg="service-account-signing-key-file=/etc/k3s/sa-signing.key" \\',
            '    --kube-apiserver-arg="service-account-key-file=/etc/k3s/sa-signing.pub" \\',
            '    --kube-apiserver-arg="api-audiences=sts.amazonaws.com" \\',
            "    --disable=traefik \\",
            "    --flannel-backend=vxlan \\",
            "    --node-taint=node-role.kubernetes.io/control-plane:NoSchedule",
            "",
            "# Signal ready (init node only — harmless duplicate writes on joiners)",
            'until kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes >/dev/null 2>&1; do',
            "    sleep 5",
            "done",
            'aws ssm put-parameter --region "$REGION" '
            '--name "$READY_PARAM" --value "true" --type String --overwrite',
        )
        return ud

    # ── NLB Target Groups + Listeners ─────────────────────────────────────────

    def _build_nlb_listeners(
        self,
        nlb: elbv2.NetworkLoadBalancer,
        vpc: ec2.Vpc,
        cp_asg: autoscaling.AutoScalingGroup,
    ) -> None:
        def _tcp_target_group(construct_id, port):
            return elbv2.NetworkTargetGroup(self, construct_id,
                vpc=vpc,
                port=port,
                protocol=elbv2.Protocol.TCP,
                targets=[cp_asg],
                health_check=elbv2.HealthCheck(
                    protocol=elbv2.Protocol.TCP,
                    port=str(port),
                    healthy_threshold_count=2,
                    unhealthy_threshold_count=2,
                    interval=Duration.seconds(10),
                ),
            )

        api_tg = _tcp_target_group("K3sApiTG", 6443)
        nlb.add_listener("K3sApiListener",
            port=6443,
            protocol=elbv2.Protocol.TCP,
            default_target_groups=[api_tg],
        )

        supervisor_tg = _tcp_target_group("K3sSupervisorTG", 9345)
        nlb.add_listener("K3sSupervisorListener",
            port=9345,
            protocol=elbv2.Protocol.TCP,
            default_target_groups=[supervisor_tg],
        )

    # ── Tailscale Subnet Router ───────────────────────────────────────────────

    def _build_tailscale(
        self,
        vpc: ec2.Vpc,
        tailscale_role: iam.Role,
        tailscale_sg: ec2.SecurityGroup,
    ) -> None:
        ud = ec2.UserData.for_linux()
        ud.add_commands(
            "set -euo pipefail",
            f'REGION="{self.region}"',
            f'TS_SECRET_ID="{self.cluster_name}/tailscale-auth-key"',
            f'VPC_CIDR="{vpc.vpc_cidr_block}"',
            "",
            "# Enable IP forwarding",
            "echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-tailscale.conf",
            "sysctl -p /etc/sysctl.d/99-tailscale.conf",
            "",
            "# Install Tailscale",
            "curl -fsSL https://tailscale.com/install.sh | sh",
            "systemctl enable --now tailscaled",
            "",
            "# Fetch auth key and connect",
            'AUTH_KEY=$(aws secretsmanager get-secret-value'
            ' --region "$REGION" --secret-id "$TS_SECRET_ID"'
            ' --query SecretString --output text)',
            'tailscale up --authkey="$AUTH_KEY"'
            ' --advertise-routes="$VPC_CIDR"'
            " --accept-dns=false",
        )

        launch_template = ec2.LaunchTemplate(self, "TailscaleLT",
            instance_type=ec2.InstanceType("t4g.nano"),
            machine_image=ec2.MachineImage.latest_amazon_linux2023(
                cpu_type=ec2.AmazonLinuxCpuType.ARM_64),
            role=tailscale_role,
            security_group=tailscale_sg,
            user_data=ud,
            require_imdsv2=True,
        )

        autoscaling.AutoScalingGroup(self, "TailscaleASG",
            vpc=vpc,
            launch_template=launch_template,
            min_capacity=1,
            max_capacity=1,
            desired_capacity=1,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
        )

    # ── Outputs ───────────────────────────────────────────────────────────────

    def _build_outputs(
        self,
        nlb: elbv2.NetworkLoadBalancer,
        issuer_url: str,
        cluster_token: sm.Secret,
        karpenter_role: iam.Role,
        node_profile: iam.CfnInstanceProfile,
        interruption_queue: sqs.Queue,
    ) -> None:
        CfnOutput(self, "NlbDns",
            value=nlb.load_balancer_dns_name,
            description="k3s API server endpoint (access via Tailscale)")
        CfnOutput(self, "OidcIssuer",
            value=issuer_url,
            description="OIDC issuer URL for IRSA")
        CfnOutput(self, "ClusterTokenSecretArn",
            value=cluster_token.secret_arn,
            description="Secrets Manager ARN for k3s cluster token")
        CfnOutput(self, "KarpenterControllerRoleArn",
            value=karpenter_role.role_arn,
            description="Karpenter controller IRSA role ARN")
        CfnOutput(self, "KarpenterNodeInstanceProfileName",
            value=node_profile.ref,
            description="Instance profile name for Karpenter-launched nodes")
        CfnOutput(self, "KarpenterInterruptionQueueName",
            value=interruption_queue.queue_name,
            description="SQS queue name for Karpenter interruption handling")

#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME=${1:-llamadist}

kubectl create namespace external-secrets --dry-run=client -o yaml | kubectl apply -f -

ROLE_ARN="$(aws ssm get-parameter \
  --name "/${CLUSTER_NAME}/eso/controller-role-arn" \
  --query Parameter.Value --output text)"

kubectl create secret generic eso-irsa-config \
  --namespace external-secrets \
  --from-literal=roleArn="${ROLE_ARN}" \
  --dry-run=client -o yaml | kubectl apply -f -
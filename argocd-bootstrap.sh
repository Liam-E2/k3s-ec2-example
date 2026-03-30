#!/usr/bin/env bash
helm repo add argo https://argoproj.github.io/argo-helm
helm repo update

helm upgrade --install argocd argo/argo-cd \
  --namespace argocd \
  --create-namespace \
  --set server.service.type=ClusterIP \
  --set controller.extraArgs="{--loglevel=info}" \
  --set server.ingress.enabled=false \
  --set global.tolerations[0].key=node-role.kubernetes.io/control-plane \
  --set global.tolerations[0].operator=Exists \
  --set global.tolerations[0].effect=NoSchedule \
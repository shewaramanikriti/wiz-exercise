#!/usr/bin/env bash
# Delete the exercise in reverse dependency order.
# The Ingress is removed first: its ALB is created by Kubernetes, not
# CloudFormation, and would otherwise block VPC deletion.
set -euo pipefail
PROJECT="${PROJECT:-wiz}"
REGION="${AWS_REGION:-us-east-1}"
export AWS_REGION="$REGION"

stack_exists() { aws cloudformation describe-stacks --stack-name "$1" >/dev/null 2>&1; }
delete_stack() {
  if stack_exists "$1"; then
    echo ">> deleting $1"
    aws cloudformation delete-stack --stack-name "$1"
    aws cloudformation wait stack-delete-complete --stack-name "$1"
  fi
}

if stack_exists "$PROJECT-eks"; then
  aws eks update-kubeconfig --name "$PROJECT-eks" --region "$REGION" >/dev/null || true
  kubectl -n tasky delete ingress tasky --ignore-not-found --wait=true || true
  echo ">> waiting 90s for the ALB to be deprovisioned"; sleep 90
  kubectl delete namespace tasky --ignore-not-found --wait=true || true
fi
delete_stack "$PROJECT-eks"

BUCKET="$PROJECT-db-backups-$(aws sts get-caller-identity --query Account --output text)-$REGION"
if aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
  echo ">> emptying $BUCKET (all versions)"
  while :; do
    BATCH=$(aws s3api list-object-versions --bucket "$BUCKET" --max-items 500 --output json \
      | jq '{Objects: ([.Versions[]?, .DeleteMarkers[]?] | map({Key, VersionId})), Quiet: true}')
    [ "$(jq '.Objects | length' <<<"$BATCH")" -eq 0 ] && break
    aws s3api delete-objects --bucket "$BUCKET" --delete "$BATCH" >/dev/null
  done
fi
delete_stack "$PROJECT-mongodb"
delete_stack "$PROJECT-security"   # CloudTrail/Config buckets are retained on purpose (audit evidence)
delete_stack "$PROJECT-network"
echo "Done. The bootstrap stack ($PROJECT-github-oidc) is left in place; delete it manually last."

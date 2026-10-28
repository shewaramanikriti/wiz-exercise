#!/usr/bin/env bash
# Sourced by verify-weaknesses.sh. Keep command failures distinct from empty data.
VERIFY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
evidence() { python3 "$VERIFY_DIR/evidence_checks.py" "$@"; }

nodes_private() {
  local nodes ids instances
  nodes=$(kubectl get nodes -o json) || return 1
  ids=$(printf '%s' "$nodes" | evidence instance-ids) || return 1
  # IDs are validated by evidence_checks.py before intentional word splitting.
  instances=$(aws ec2 describe-instances --instance-ids $ids --output json) || return 1
  printf '%s' "$instances" | evidence instances "$PRIVATE_SUBNET_1" "$PRIVATE_SUBNET_2" $ids
}

mongo_network_restricted() {
  local groups
  groups=$(aws ec2 describe-security-groups --group-ids $SG --output json) || return 1
  printf '%s' "$groups" | evidence mongo-sg "$PRIVATE_CIDR_1" "$PRIVATE_CIDR_2" || return 1
  # SG evidence is required first: a failed network probe alone proves little.
  ! $NC "$IP" 27017
}

public_backup_key() {
  local listing
  listing=$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix backups/ \
    --no-sign-request --output json) || return 1
  printf '%s' "$listing" | evidence backup-key
}

public_backup_readable() {
  local key
  key=$(public_backup_key) || return 1
  aws s3api get-object --bucket "$BUCKET" --key "$key" --no-sign-request \
    "$VERIFY_TMP/public-backup.archive.gz" >/dev/null || return 1
  test -s "$VERIFY_TMP/public-backup.archive.gz"
}

vm_has_admin_policy() {
  local arn version action
  arn=$(aws iam list-attached-role-policies --role-name "$ROLE" \
    --query "AttachedPolicies[?contains(PolicyName,'overly-permissive')].PolicyArn | [0]" --output text) || return 1
  [ -n "$arn" ] && [ "$arn" != None ] || return 1
  version=$(aws iam get-policy --policy-arn "$arn" --query 'Policy.DefaultVersionId' --output text) || return 1
  action=$(aws iam get-policy-version --policy-arn "$arn" --version-id "$version" \
    --query 'PolicyVersion.Document.Statement[0].Action' --output text) || return 1
  [ "$action" = '*' ]
}

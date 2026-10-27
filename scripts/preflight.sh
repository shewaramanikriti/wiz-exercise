#!/usr/bin/env bash
# Run FIRST, right after you get CloudLabs credentials. Read-only: it changes nothing.
# It answers the questions that can only be answered from inside the account and
# prints the exact GitHub variables and bootstrap command to use.
#
# Usage: AWS_REGION=us-east-1 GITHUB_ORG=<org> GITHUB_REPO=<repo> ./scripts/preflight.sh
set -uo pipefail
export AWS_REGION="${AWS_REGION:-us-east-1}"
PROJECT="${PROJECT:-wiz}"
GITHUB_ORG="${GITHUB_ORG:-<your-github-org-or-user>}"
GITHUB_REPO="${GITHUB_REPO:-<your-repo>}"

ok()   { printf '  \033[32m[OK]\033[0m     %s\n' "$*"; }
act()  { printf '  \033[33m[ACTION]\033[0m %s\n' "$*"; ACTIONS=$((ACTIONS+1)); }
bad()  { printf '  \033[31m[BLOCKER]\033[0m %s\n' "$*"; BLOCKERS=$((BLOCKERS+1)); }
ACTIONS=0; BLOCKERS=0
VAR_GD=true; VAR_CFG=true; VAR_SH=true; OIDC_PARAM=true

echo "== Tools on this machine"
for t in aws git jq kubectl ssh nc curl; do
  command -v "$t" >/dev/null && ok "$t" || act "install $t"
done
aws --version 2>&1 | grep -q 'aws-cli/2' || act "AWS CLI v2 recommended"

echo "== Identity and region ($AWS_REGION)"
if ! ID=$(aws sts get-caller-identity --output json 2>/dev/null); then
  bad "No working AWS credentials. Export the CloudLabs keys or use CloudShell."; exit 1
fi
ACCOUNT=$(jq -r .Account <<<"$ID"); ARN=$(jq -r .Arn <<<"$ID")
ok "account $ACCOUNT as $ARN"
if [[ "$ARN" == *":assumed-role/"* ]]; then
  ROLE_NAME=$(cut -d/ -f2 <<<"$ARN")
  ADMIN_ARN=$(aws iam get-role --role-name "$ROLE_NAME" --query Role.Arn --output text 2>/dev/null \
              || echo "arn:aws:iam::$ACCOUNT:role/$ROLE_NAME")
else
  ADMIN_ARN="$ARN"
fi
ok "EKS_ADMIN_PRINCIPAL_ARN will be $ADMIN_ARN"
AZS=$(aws ec2 describe-availability-zones --query 'length(AvailabilityZones[?State==`available`])' --output text 2>/dev/null || echo 0)
[ "${AZS:-0}" -ge 2 ] && ok "$AZS AZs available" || bad "region $AWS_REGION unusable or blocked (need >= 2 AZs)"
[ "$AWS_REGION" = "us-east-1" ] || act "IAM API events only reach EventBridge in us-east-1; the IAM part of the tampering alert won't fire in $AWS_REGION"

echo "== Account-level S3 Block Public Access (must allow the public backup bucket)"
BPA=$(aws s3control get-public-access-block --account-id "$ACCOUNT" --output json 2>&1)
if grep -q NoSuchPublicAccessBlockConfiguration <<<"$BPA"; then
  ok "no account-level block"
elif grep -q '"BlockPublicPolicy": true\|"RestrictPublicBuckets": true' <<<"$BPA"; then
  act "account-level BPA blocks public policies. Turn it off (if CloudLabs allows):
             aws s3control delete-public-access-block --account-id $ACCOUNT"
elif grep -qi 'AccessDenied' <<<"$BPA"; then
  act "cannot read account BPA (AccessDenied) - ask the CloudLabs/hiring contact whether public buckets are allowed"
else
  ok "account-level BPA does not block bucket policies"
fi

echo "== One-per-region security services (decides GitHub variables)"
GD=$(aws guardduty list-detectors --query 'length(DetectorIds)' --output text 2>/dev/null || echo err)
case "$GD" in 0) ok "no GuardDuty detector - stack will create one";;
  err) act "cannot query GuardDuty (permissions?)";;
  *) VAR_GD=false; ok "GuardDuty already enabled - set CREATE_GUARDDUTY=false";; esac
CR=$(aws configservice describe-configuration-recorders --query 'length(ConfigurationRecorders)' --output text 2>/dev/null || echo err)
case "$CR" in 0) ok "no Config recorder - stack will create one";;
  err) act "cannot query AWS Config (permissions?)";;
  *) VAR_CFG=false; ok "Config recorder exists - set CREATE_CONFIG_RECORDER=false";; esac
if aws securityhub describe-hub >/dev/null 2>&1; then VAR_SH=false; ok "Security Hub already on - set ENABLE_SECURITY_HUB=false"
else ok "Security Hub off - stack will enable it"; fi
if aws iam list-open-id-connect-providers --output text 2>/dev/null | grep -q token.actions.githubusercontent.com; then
  OIDC_PARAM=false; ok "GitHub OIDC provider exists - bootstrap with CreateOidcProvider=false"
else ok "no GitHub OIDC provider - bootstrap will create it"; fi

echo "== Images and quotas"
AMI=$(aws ssm get-parameter --name /aws/service/canonical/ubuntu/server/20.04/stable/current/amd64/hvm/ebs-gp2/ami-id \
      --query Parameter.Value --output text 2>/dev/null)
[ -n "$AMI" ] && ok "Ubuntu 20.04 AMI $AMI" || act "Ubuntu 20.04 SSM parameter missing - find an AMI id and pass MongoAmiId"
EIP_Q=$(aws service-quotas get-service-quota --service-code ec2 --quota-code L-0263D0A3 --query Quota.Value --output text 2>/dev/null || echo 5)
EIP_U=$(aws ec2 describe-addresses --query 'length(Addresses)' --output text 2>/dev/null || echo 0)
awk "BEGIN{exit !($EIP_Q - $EIP_U >= 2)}" && ok "Elastic IPs: $EIP_U used of ${EIP_Q%.*} (need 2)" || bad "not enough Elastic IPs ($EIP_U/${EIP_Q%.*}, need 2 free)"
VPC_Q=$(aws service-quotas get-service-quota --service-code vpc --quota-code L-F678F1CE --query Quota.Value --output text 2>/dev/null || echo 5)
VPC_U=$(aws ec2 describe-vpcs --query 'length(Vpcs)' --output text 2>/dev/null || echo 0)
awk "BEGIN{exit !($VPC_Q - $VPC_U >= 1)}" && ok "VPCs: $VPC_U used of ${VPC_Q%.*}" || bad "VPC quota full ($VPC_U/${VPC_Q%.*})"
EKSV=$(aws eks describe-cluster-versions --default-only --query 'clusterVersions[0].clusterVersion' --output text 2>/dev/null)
[ -n "$EKSV" ] && [ "$EKSV" != "None" ] && ok "EKS default version $EKSV" || ok "EKS reachable (default version lookup unsupported by this CLI)"

echo "== Permission probe (identity policy only; SCPs are NOT reflected)"
if [[ "$ADMIN_ARN" == arn:aws:iam::* ]]; then
  DENIED=$(aws iam simulate-principal-policy --policy-source-arn "$ADMIN_ARN" \
    --action-names iam:CreateRole iam:CreateOpenIDConnectProvider eks:CreateCluster ec2:RunInstances \
      ec2:CreateNatGateway cloudtrail:CreateTrail guardduty:CreateDetector config:PutConfigurationRecorder \
      securityhub:EnableSecurityHub s3:PutBucketPolicy secretsmanager:CreateSecret cloudformation:CreateStack \
    --query "EvaluationResults[?EvalDecision!='allowed'].EvalActionName" --output text 2>/dev/null)
  if [ $? -ne 0 ]; then act "cannot simulate permissions; the bootstrap deploy will be the real test"
  elif [ -n "$DENIED" ]; then bad "not allowed: $DENIED"
  else ok "all key actions allowed by identity policy"; fi
fi

cat <<EOF

== Values to use
Bootstrap (run once):
  aws cloudformation deploy --region $AWS_REGION --stack-name $PROJECT-github-oidc \\
    --template-file cloudformation/00-github-oidc.yaml --capabilities CAPABILITY_NAMED_IAM \\
    --parameter-overrides ProjectName=$PROJECT GitHubOrg=$GITHUB_ORG GitHubRepo=$GITHUB_REPO CreateOidcProvider=$OIDC_PARAM

GitHub repository variables:
  AWS_REGION=$AWS_REGION
  PROJECT_NAME=$PROJECT
  EKS_ADMIN_PRINCIPAL_ARN=$ADMIN_ARN
  CREATE_GUARDDUTY=$VAR_GD
  CREATE_CONFIG_RECORDER=$VAR_CFG
  ENABLE_SECURITY_HUB=$VAR_SH
  ALERT_EMAIL=<your email>         (optional)

Summary: $BLOCKERS blocker(s), $ACTIONS action(s).
EOF
[ "$BLOCKERS" -eq 0 ]

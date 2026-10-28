#!/usr/bin/env bash
# Simulated attack path against YOUR OWN exercise environment, to show each
# weakness, its consequence, and which control prevented or detected it.
# Only run against the lab account you deployed.
set -u   # explicit refusal handling below; no destructive deny-test commands
umask 077
DEMO_TMP=$(mktemp -d) || exit 2
trap 'rm -rf -- "$DEMO_TMP"' EXIT
PROJECT="${PROJECT:-wiz}"; export AWS_REGION="${AWS_REGION:-us-east-1}"
out() { aws cloudformation describe-stacks --stack-name "$PROJECT-$1" \
          --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text; }
step() { printf '\n\033[1;31m>> %s\033[0m\n' "$*"; read -rp "(enter) " _; }

BUCKET=$(out mongodb BackupBucketName); MONGO_PUB=$(out mongodb MongoPublicIp)
KEY_ID=$(out mongodb KeyPairId); CLUSTER=$(out eks ClusterName)
aws ssm get-parameter --name "/ec2/keypair/$KEY_ID" --with-decryption \
  --query Parameter.Value --output text > "$DEMO_TMP/mongo.pem" || exit 2

step "A1. Anonymous internet user lists and downloads DB backups (W5)"
curl -s "https://$BUCKET.s3.$AWS_REGION.amazonaws.com/?list-type=2" | grep -o '<Key>[^<]*</Key>' | tail -3
LATEST=$(curl -s "https://$BUCKET.s3.$AWS_REGION.amazonaws.com/?list-type=2&prefix=backups/" \
         | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g' | sort | tail -1)
curl -s -o "$DEMO_TMP/public-demo.archive.gz" "https://$BUCKET.s3.$AWS_REGION.amazonaws.com/$LATEST"
echo "Downloaded $(du -h "$DEMO_TMP/public-demo.archive.gz" | cut -f1) without credentials. Field names inside:"
gunzip -c "$DEMO_TMP/public-demo.archive.gz" | strings | grep -E '^(email|password|name|go-mongodb)' | sort -u | head
echo "Config/Security Hub report the public-bucket posture. Show a matching delivered CloudTrail event before claiming this download was observed."

step "A2. SSH open to the internet leaks an outdated OpenSSH banner (W1, W2)"
ssh-keyscan -T 5 "$MONGO_PUB" 2>&1 | grep -m1 -i openssh || true
echo "Config/Security Hub can flag open SSH. A banner check alone is not evidence of GuardDuty brute-force detection."

step "A3. Abuse the VM's over-permissive instance role (W3)"
ssh -o StrictHostKeyChecking=accept-new -i "$DEMO_TMP/mongo.pem" "ubuntu@$MONGO_PUB" '
  set +e
  export AWS_DEFAULT_REGION='"$AWS_REGION"'
  TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
  md() { curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/$1; }
  AMI=$(md ami-id); MAC=$(md mac); SUBNET=$(md network/interfaces/macs/$MAC/subnet-id)
  echo "--- identity:"; aws sts get-caller-identity --output text
  echo "--- can I launch VMs? (dry run)"
  aws ec2 run-instances --dry-run --image-id "$AMI" --instance-type t3.micro --subnet-id "$SUBNET" 2>&1 | tail -1
  echo "--- can I list bucket names? (not proof of object reads)"; aws s3 ls | head -5
  echo "--- can I list secret metadata? (not proof of secret-value access)"; aws secretsmanager list-secrets --query "SecretList[].Name" --output text
  echo "--- read-only checks complete; no logging-disable, detector-delete or user-create calls were made."'
step "P0. Simulate the VM role policy for the specific denied actions"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text) || exit 2
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::$ACCOUNT:role/$PROJECT-mongodb-vm-role" \
  --action-names cloudtrail:StopLogging guardduty:DeleteDetector iam:CreateUser \
  --query 'EvaluationResults[].{action:EvalActionName,decision:EvalDecision,boundary:PermissionsBoundaryDecisionDetail.AllowedByPermissionsBoundary}' \
  --output table || exit 2
echo "Expected: explicitDeny. This is policy simulation, not a real blocked API call or an end-to-end alert test."
echo "The boundary covers named actions only; it is not a guarantee against account takeover."

step "A4. Code execution in the app pod = cluster-admin (Kubernetes RBAC weakness)"
aws eks update-kubeconfig --name "$CLUSTER" --region "$AWS_REGION" >/dev/null
kubectl auth can-i --list --as=system:serviceaccount:tasky:tasky-sa | head -5
kubectl auth can-i list secrets --all-namespaces --as=system:serviceaccount:tasky:tasky-sa
kubectl -n tasky get deploy tasky -o jsonpath='{.spec.template.spec.serviceAccountName}{"\n"}'
kubectl -n tasky exec deploy/tasky -- test -s /var/run/secrets/kubernetes.io/serviceaccount/token
echo "This checks authorization and the mounted token without fetching any Secret values."
echo "EKS audit logs record API activity. Claim a GuardDuty detection only when a matching finding exists."

step "A5. Connection logging: the reviewed app must not print credentials"
kubectl -n tasky logs deploy/tasky | sed -E 's#//([^:]+):[^@]+@#//\1:****@#g' | grep -E 'MongoDB client configured|Connected to MONGO'
echo "The patch logs only client configuration. Old pods may still log a URI; rotate the exposed lab password after rollout."

step "P1. Preventative control: Pod Security Admission blocks a privileged pod"
kubectl -n tasky run escape --image=alpine --restart=Never --dry-run=server -o yaml \
  --overrides='{"spec":{"containers":[{"name":"escape","image":"alpine","securityContext":{"privileged":true}}]}}' 2>&1 | tail -2 || true

step "D1. Generate labelled GuardDuty SAMPLE findings -> EventBridge -> SNS (creates sample findings)"
DET=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty create-sample-findings --detector-id "$DET" \
  --finding-types "UnauthorizedAccess:EC2/SSHBruteForce" "Policy:Kubernetes/AdminAccessToDefaultServiceAccount" \
  "Policy:S3/BucketAnonymousAccessGranted"
echo "Check GuardDuty and the alert destination. Sample findings test delivery, not detection of an actual attack. Allow for delivery delay."

step "D2. Inspect previous real attempts, if any (simulation above does not create StopLogging events)"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --max-results 3 --query 'Events[].{time:EventTime,user:Username,event:EventName}' --output table
echo "For S3 data events inspect delivered trail logs; event history omits data events. CloudTrail Lake is not provisioned by this repo."

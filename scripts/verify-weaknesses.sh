#!/usr/bin/env bash
# Pre-demo check: confirms every INTENTIONAL weakness the exercise requires is
# live, and every REQUIRED restriction is in place. Read-only; changes nothing.
# Usage: PROJECT=wiz AWS_REGION=us-east-1 ./scripts/verify-weaknesses.sh
set -u
for tool in aws kubectl python3 ssh nc curl; do
  command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 2; }
done
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/verify_helpers.sh"
umask 077
VERIFY_TMP=$(mktemp -d) || exit 2
trap 'rm -rf -- "$VERIFY_TMP"' EXIT
PROJECT="${PROJECT:-wiz}"; export AWS_REGION="${AWS_REGION:-us-east-1}"
NC="nc -z -w 3"; nc -h 2>&1 | grep -q -- "-G" && NC="nc -z -G 3 -w 3"   # macOS nc ignores -w while connecting; -G is its connect timeout
out() {
  local value
  value=$(aws cloudformation describe-stacks --stack-name "$PROJECT-$1" \
    --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text) || return 1
  [ -n "$value" ] && [ "$value" != None ] || return 1
  printf '%s' "$value"
}
PASS=0; FAIL=0
check() { if eval "$2" >/dev/null 2>&1; then echo "  [OK]   $1"; PASS=$((PASS+1)); else echo "  [FAIL] $1"; FAIL=$((FAIL+1)); fi; }

BUCKET=$(out mongodb BackupBucketName) || exit 2
IP=$(out mongodb MongoPublicIp) || exit 2
KEY_ID=$(out mongodb KeyPairId) || exit 2
IID=$(out mongodb MongoInstanceId) || exit 2
CLUSTER=$(out eks ClusterName) || exit 2
PRIVATE_SUBNET_1=$(out network PrivateSubnet1) || exit 2
PRIVATE_SUBNET_2=$(out network PrivateSubnet2) || exit 2
PRIVATE_CIDR_1=$(out network PrivateSubnet1Cidr) || exit 2
PRIVATE_CIDR_2=$(out network PrivateSubnet2Cidr) || exit 2
aws ssm get-parameter --name "/ec2/keypair/$KEY_ID" --with-decryption --query Parameter.Value --output text > "$VERIFY_TMP/mongo.pem" || exit 2
SSH="ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -i $(printf %q "$VERIFY_TMP/mongo.pem") ubuntu@$IP"
SG=$(aws ec2 describe-instances --instance-ids "$IID" --query 'Reservations[0].Instances[0].SecurityGroups[].GroupId' --output text) || exit 2
ROLE="$PROJECT-mongodb-vm-role"
aws eks update-kubeconfig --name "$CLUSTER" >/dev/null || exit 2

echo "INTENTIONAL WEAKNESSES (must all be OK)"
check "VM OS is Ubuntu 20.04 (outside standard support)"                  "$SSH 'lsb_release -rs' | grep -q '^20.04'"
check "Automatic OS patching disabled"               "$SSH 'systemctl is-enabled unattended-upgrades' | grep -qxE 'disabled|masked'"
check "SSH (22) open to 0.0.0.0/0 in security group" "aws ec2 describe-security-groups --group-ids $SG --query \"SecurityGroups[0].IpPermissions[?FromPort==\\\`22\\\`].IpRanges[].CidrIp\" --output text | grep -q '0.0.0.0/0'"
check "SSH reachable from the internet"              "$NC $IP 22"
check "VM role has an Action:* policy (current default version)" "vm_has_admin_policy"
check "VM role can create VMs (dry-run succeeds)"    "$SSH 'export AWS_DEFAULT_REGION=$AWS_REGION; T=\$(curl -s -X PUT http://169.254.169.254/latest/api/token -H \"X-aws-ec2-metadata-token-ttl-seconds: 60\"); M(){ curl -s -H \"X-aws-ec2-metadata-token: \$T\" http://169.254.169.254/latest/meta-data/\$1; }; aws ec2 run-instances --dry-run --image-id \$(M ami-id) --instance-type t3.micro --subnet-id \$(M network/interfaces/macs/\$(M mac)/subnet-id) 2>&1' | grep -q DryRunOperation"
check "MongoDB is an EOL version (< 7.0)"           "$SSH 'mongod --version' | grep -Eq 'db version v(4\.|5\.|6\.)'"
check "Daily backup cron job present"                "$SSH 'cat /etc/cron.d/mongo-backup' | grep -q mongo-backup.sh"
check "Backup object exists in S3"                   "aws s3 ls s3://$BUCKET/backups/ | grep -q archive.gz"
check "Bucket publicly LISTABLE with a non-empty backup" "public_backup_key"
check "Backups publicly READABLE (anonymous GetObject)" "public_backup_readable"
check "App SA bound to cluster-admin"                "kubectl get clusterrolebinding tasky-sa-cluster-admin -o jsonpath='{.roleRef.name}' | grep -qx cluster-admin"
check "App SA can do anything cluster-wide"          "kubectl auth can-i '*' '*' --all-namespaces --as=system:serviceaccount:tasky:tasky-sa | grep -qx yes"

echo "REQUIRED RESTRICTIONS (must all be OK)"
check "MongoDB SG restricts 27017 to private subnets; public probe fails" "mongo_network_restricted"
check "MongoDB rejects unauthenticated reads"        "$SSH '\$(command -v mongosh || command -v mongo) --quiet go-mongodb --eval \"db.todos.findOne()\" 2>&1' | grep -qiE 'requires authentication|Unauthorized'"
check "Ready EKS nodes exist in private subnets without public IPs" "nodes_private"
check "MONGODB_URI comes from a K8s env var"         "kubectl -n tasky exec deploy/tasky -- sh -c 'test -n \"\$MONGODB_URI\"'"
check "wizexercise.txt in running container"         "kubectl -n tasky exec deploy/tasky -- cat /app/wizexercise.txt | grep -qv 'REPLACE WITH'"
check "Ingress has an ALB hostname"                  "kubectl -n tasky get ingress tasky -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' | grep -q elb.amazonaws.com"

echo; echo "Result: $PASS OK, $FAIL FAIL"; [ "$FAIL" -eq 0 ]

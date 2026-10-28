#!/usr/bin/env bash
# Pre-demo check: confirms every INTENTIONAL weakness the exercise requires is
# live, and every REQUIRED restriction is in place. Read-only; changes nothing.
# Usage: PROJECT=wiz AWS_REGION=us-east-1 ./scripts/verify-weaknesses.sh
set -u   # no pipefail: checks are judged by the final grep
PROJECT="${PROJECT:-wiz}"; export AWS_REGION="${AWS_REGION:-us-east-1}"
NC="nc -z -w 3"; nc -h 2>&1 | grep -q -- "-G" && NC="nc -z -G 3 -w 3"   # macOS nc ignores -w while connecting; -G is its connect timeout
out() { aws cloudformation describe-stacks --stack-name "$PROJECT-$1" \
          --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text; }
PASS=0; FAIL=0
check() { if eval "$2" >/dev/null 2>&1; then echo "  [OK]   $1"; PASS=$((PASS+1)); else echo "  [FAIL] $1"; FAIL=$((FAIL+1)); fi; }

BUCKET=$(out mongodb BackupBucketName); IP=$(out mongodb MongoPublicIp)
KEY_ID=$(out mongodb KeyPairId); IID=$(out mongodb MongoInstanceId); CLUSTER=$(out eks ClusterName)
aws ssm get-parameter --name "/ec2/keypair/$KEY_ID" --with-decryption --query Parameter.Value --output text > /tmp/mongo.pem; chmod 600 /tmp/mongo.pem
SSH="ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -i /tmp/mongo.pem ubuntu@$IP"
SG=$(aws ec2 describe-instances --instance-ids "$IID" --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text)
ROLE="$PROJECT-mongodb-vm-role"
aws eks update-kubeconfig --name "$CLUSTER" >/dev/null 2>&1

echo "INTENTIONAL WEAKNESSES (must all be OK)"
check "VM OS is Ubuntu 20.04 (EOL)"                  "$SSH 'lsb_release -rs' | grep -q '^20.04'"
check "Automatic OS patching disabled"               "$SSH 'systemctl is-enabled unattended-upgrades' | grep -qv '^enabled'"
check "SSH (22) open to 0.0.0.0/0 in security group" "aws ec2 describe-security-groups --group-ids $SG --query \"SecurityGroups[0].IpPermissions[?FromPort==\\\`22\\\`].IpRanges[].CidrIp\" --output text | grep -q '0.0.0.0/0'"
check "SSH reachable from the internet"              "$NC $IP 22"
check "VM role has an Action:* (admin-level) policy" "aws iam get-policy-version --policy-arn \$(aws iam list-attached-role-policies --role-name $ROLE --query \"AttachedPolicies[?contains(PolicyName,'overly-permissive')].PolicyArn\" --output text) --version-id v1 --query 'PolicyVersion.Document.Statement[0].Action' --output text | grep -qx '\*'"
check "VM role can create VMs (dry-run succeeds)"    "$SSH 'export AWS_DEFAULT_REGION=$AWS_REGION; T=\$(curl -s -X PUT http://169.254.169.254/latest/api/token -H \"X-aws-ec2-metadata-token-ttl-seconds: 60\"); M(){ curl -s -H \"X-aws-ec2-metadata-token: \$T\" http://169.254.169.254/latest/meta-data/\$1; }; aws ec2 run-instances --dry-run --image-id \$(M ami-id) --instance-type t3.micro --subnet-id \$(M network/interfaces/macs/\$(M mac)/subnet-id) 2>&1' | grep -q DryRunOperation"
check "MongoDB is an EOL version (< 7.0)"           "$SSH 'mongod --version' | grep -Eq 'db version v(4\.|5\.|6\.)'"
check "Daily backup cron job present"                "$SSH 'cat /etc/cron.d/mongo-backup' | grep -q mongo-backup.sh"
check "Backup object exists in S3"                   "aws s3 ls s3://$BUCKET/backups/ | grep -q archive.gz"
check "Bucket publicly LISTABLE (anonymous)"         "curl -sf 'https://$BUCKET.s3.$AWS_REGION.amazonaws.com/?list-type=2' | grep -q '<Key>'"
check "Backups publicly READABLE (anonymous)"        "K=\$(curl -s 'https://$BUCKET.s3.$AWS_REGION.amazonaws.com/?list-type=2&prefix=backups/' | grep -o '<Key>[^<]*' | head -1 | cut -c6-); curl -sf -o /dev/null https://$BUCKET.s3.$AWS_REGION.amazonaws.com/\$K"
check "App SA bound to cluster-admin"                "kubectl get clusterrolebinding tasky-sa-cluster-admin -o jsonpath='{.roleRef.name}' | grep -qx cluster-admin"
check "App SA can do anything cluster-wide"          "kubectl auth can-i '*' '*' --all-namespaces --as=system:serviceaccount:tasky:tasky-sa | grep -qx yes"

echo "REQUIRED RESTRICTIONS (must all be OK)"
check "MongoDB 27017 NOT reachable from internet"    "! $NC $IP 27017"
check "MongoDB rejects unauthenticated reads"        "$SSH '\$(command -v mongosh || command -v mongo) --quiet go-mongodb --eval \"db.todos.findOne()\" 2>&1' | grep -qiE 'requires authentication|Unauthorized'"
check "EKS nodes have no public IPs"                 "! kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type==\"ExternalIP\")].address}' | grep -q ."
check "MONGODB_URI comes from a K8s env var"         "kubectl -n tasky exec deploy/tasky -- sh -c 'test -n \"\$MONGODB_URI\"'"
check "wizexercise.txt in running container"         "kubectl -n tasky exec deploy/tasky -- cat /app/wizexercise.txt | grep -qv 'REPLACE WITH'"
check "Ingress has an ALB hostname"                  "kubectl -n tasky get ingress tasky -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' | grep -q elb.amazonaws.com"

echo; echo "Result: $PASS OK, $FAIL FAIL"; [ "$FAIL" -eq 0 ]

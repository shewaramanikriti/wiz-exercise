#!/usr/bin/env bash
# Live-walkthrough helper: proves each exercise requirement with real output.
# Usage: PROJECT=wiz AWS_REGION=us-east-1 ./scripts/demo.sh
set -u   # demo script: keep going when a step reports a refusal via a non-zero exit
PROJECT="${PROJECT:-wiz}"; export AWS_REGION="${AWS_REGION:-us-east-1}"
NC="nc -z -w 3"; nc -h 2>&1 | grep -q -- "-G" && NC="nc -z -G 3 -w 3"   # macOS nc ignores -w while connecting; -G is its connect timeout
out() { aws cloudformation describe-stacks --stack-name "$PROJECT-$1" \
          --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text; }
step() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; read -rp "(enter) " _; }

CLUSTER=$(out eks ClusterName); BUCKET=$(out mongodb BackupBucketName)
MONGO_PUB=$(out mongodb MongoPublicIp); KEY_ID=$(out mongodb KeyPairId)
aws eks update-kubeconfig --name "$CLUSTER" --region "$AWS_REGION" >/dev/null

step "1. kubectl: cluster, nodes (private IPs only), workloads"
kubectl get nodes -o wide
kubectl -n tasky get deploy,pods,svc,ingress -o wide

step "2. wizexercise.txt inside the RUNNING container"
kubectl -n tasky exec deploy/tasky -- cat /app/wizexercise.txt
kubectl -n tasky exec deploy/tasky -- ls -l /app/wizexercise.txt

step "3. MongoDB connection comes from a Kubernetes-provided env var"
kubectl -n tasky get deploy tasky -o jsonpath='{.spec.template.spec.containers[0].env}' | jq .
kubectl -n tasky exec deploy/tasky -- sh -c 'echo "$MONGODB_URI" | sed -E "s#//([^:]+):[^@]+@#//\1:****@#"'

step "4. App via the ALB (open in a browser and add a todo)"
HOST=$(kubectl -n tasky get ingress tasky -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
echo "http://$HOST"; curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://$HOST/"

step "5. Prove the data is in MongoDB (query from the VM)"
aws ssm get-parameter --name "/ec2/keypair/$KEY_ID" --with-decryption \
  --query Parameter.Value --output text > /tmp/mongo.pem && chmod 600 /tmp/mongo.pem
ssh -o StrictHostKeyChecking=accept-new -i /tmp/mongo.pem "ubuntu@$MONGO_PUB" '
  S=$(aws secretsmanager get-secret-value --region '"$AWS_REGION"' --secret-id '"$PROJECT"'/mongodb/app-user --query SecretString --output text)
  U=$(echo "$S" | jq -r .username); P=$(echo "$S" | jq -r .password)
  M=$(command -v mongosh || command -v mongo)
  $M --quiet -u "$U" -p "$P" --authenticationDatabase admin go-mongodb \
     --eval "print(\"mongo \" + db.version()); printjson(db.getCollectionNames()); print(\"users: \" + db.user.countDocuments({})); db.todos.find().limit(5).forEach(printjson)"'

step "6. Outdated OS and MongoDB versions"
ssh -i /tmp/mongo.pem "ubuntu@$MONGO_PUB" 'lsb_release -ds; mongod --version | head -1'

step "7. Daily backup job and the objects in S3"
ssh -i /tmp/mongo.pem "ubuntu@$MONGO_PUB" 'cat /etc/cron.d/mongo-backup; tail -3 /var/log/mongo-backup.log'
aws s3 ls "s3://$BUCKET/backups/" --human-readable

step "8. Mongo port is NOT reachable from the internet (only SSH is)"
$NC "$MONGO_PUB" 27017 && echo "27017 OPEN (unexpected)" || echo "27017 closed from internet - restricted to EKS subnets"
$NC "$MONGO_PUB" 22 && echo "22 open from internet (intentional weakness)"

step "9. Audit logging is on (CloudTrail + EKS control plane)"
aws cloudtrail get-trail-status --name "$PROJECT-trail" --query '{IsLogging:IsLogging,Latest:LatestDeliveryTime}'
aws eks describe-cluster --name "$CLUSTER" --query 'cluster.logging.clusterLogging[?enabled].types' --output json

step "10. Detective controls: Config non-compliance"
aws configservice describe-compliance-by-config-rule --compliance-types NON_COMPLIANT \
  --query 'ComplianceByConfigRules[].ConfigRuleName' --output table
echo "Done."

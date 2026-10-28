#!/usr/bin/env bash
# Publish exactly the archive scanned in this workflow run. A same-commit rerun
# must never silently substitute an older ECR image for the newly scanned one.
set -euo pipefail
: "${REPO_URI:?}" "${PROJECT:?}" "${LOCAL_IMAGE:?}" "${GITHUB_ENV:?}"
: "${SOURCE_SHA:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}"
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]
[[ "$GITHUB_RUN_ID" =~ ^[0-9]+$ && "$GITHUB_RUN_ATTEMPT" =~ ^[0-9]+$ ]]
sha256sum --check image.tar.gz.sha256
docker load < image.tar.gz
TAG="$SOURCE_SHA-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
docker tag "$LOCAL_IMAGE" "$REPO_URI:$TAG"
# ECR is immutable: an unexpected collision fails closed, it is not reused.
docker push "$REPO_URI:$TAG"
DIGEST=$(aws ecr describe-images --repository-name "$PROJECT/tasky" \
  --image-ids "imageTag=$TAG" --query 'imageDetails[0].imageDigest' --output text)
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "Invalid ECR digest" >&2; exit 1; }
printf 'IMAGE=%s@%s\n' "$REPO_URI" "$DIGEST" >> "$GITHUB_ENV"

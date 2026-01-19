#!/bin/bash
# ============================================================================
# LLM-Shield Deployment Script
# ============================================================================
# Deploys the unified LLM-Shield service to Google Cloud Run.
#
# Usage:
#   ./scripts/deploy.sh [environment]
#
# Environments:
#   dev     - Development environment (default)
#   staging - Staging environment
#   prod    - Production environment
#
# Prerequisites:
#   - gcloud CLI authenticated
#   - Project configured: gcloud config set project YOUR_PROJECT
#   - Secrets configured in Secret Manager
# ============================================================================

set -euo pipefail

# Configuration
ENV="${1:-dev}"
PROJECT_ID=$(gcloud config get-value project)
REGION="${REGION:-us-central1}"
SERVICE_NAME="llm-shield"
SERVICE_VERSION="1.0.0"

# Environment-specific settings
case "$ENV" in
  dev)
    MIN_INSTANCES=0
    MAX_INSTANCES=5
    MEMORY="512Mi"
    CPU="1"
    ;;
  staging)
    MIN_INSTANCES=1
    MAX_INSTANCES=10
    MEMORY="1Gi"
    CPU="1"
    ;;
  prod)
    MIN_INSTANCES=2
    MAX_INSTANCES=50
    MEMORY="2Gi"
    CPU="2"
    ;;
  *)
    echo "Unknown environment: $ENV"
    echo "Usage: $0 [dev|staging|prod]"
    exit 1
    ;;
esac

echo "============================================================"
echo "LLM-Shield Deployment"
echo "============================================================"
echo "Project:     $PROJECT_ID"
echo "Environment: $ENV"
echo "Region:      $REGION"
echo "Service:     $SERVICE_NAME-$ENV"
echo "Version:     $SERVICE_VERSION"
echo "============================================================"

# Confirm production deployment
if [[ "$ENV" == "prod" ]]; then
  read -p "Are you sure you want to deploy to PRODUCTION? (yes/no): " confirm
  if [[ "$confirm" != "yes" ]]; then
    echo "Deployment cancelled."
    exit 0
  fi
fi

# Step 1: Create/update service account
echo ""
echo "[1/5] Configuring service account..."
if ! gcloud iam service-accounts describe "llm-shield-sa@${PROJECT_ID}.iam.gserviceaccount.com" &>/dev/null; then
  gcloud iam service-accounts create llm-shield-sa \
    --display-name="LLM-Shield Service Account" \
    --description="Service account for LLM-Shield unified service"
fi

# Grant required roles
for role in "secretmanager.secretAccessor" "cloudtrace.agent" "logging.logWriter" "run.invoker"; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:llm-shield-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/$role" \
    --quiet
done

# Step 2: Verify secrets exist
echo ""
echo "[2/5] Verifying secrets in Secret Manager..."
REQUIRED_SECRETS=("ruvector-service-url" "ruvector-api-key" "telemetry-endpoint")
for secret in "${REQUIRED_SECRETS[@]}"; do
  if ! gcloud secrets describe "$secret" &>/dev/null; then
    echo "ERROR: Required secret '$secret' not found in Secret Manager."
    echo "Create it with: gcloud secrets create $secret --replication-policy=automatic"
    exit 1
  fi
done
echo "All required secrets found."

# Step 3: Build and push Docker image
echo ""
echo "[3/5] Building and pushing Docker image..."
IMAGE_TAG="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:${ENV}-$(date +%Y%m%d%H%M%S)"

docker build \
  -t "$IMAGE_TAG" \
  -t "gcr.io/${PROJECT_ID}/${SERVICE_NAME}:${ENV}" \
  -t "gcr.io/${PROJECT_ID}/${SERVICE_NAME}:latest" \
  -f Dockerfile \
  .

docker push "$IMAGE_TAG"
docker push "gcr.io/${PROJECT_ID}/${SERVICE_NAME}:${ENV}"
docker push "gcr.io/${PROJECT_ID}/${SERVICE_NAME}:latest"

# Step 4: Deploy to Cloud Run
echo ""
echo "[4/5] Deploying to Cloud Run..."
gcloud run deploy "${SERVICE_NAME}-${ENV}" \
  --image "$IMAGE_TAG" \
  --region "$REGION" \
  --platform managed \
  --allow-unauthenticated \
  --memory "$MEMORY" \
  --cpu "$CPU" \
  --concurrency 80 \
  --timeout 300 \
  --min-instances "$MIN_INSTANCES" \
  --max-instances "$MAX_INSTANCES" \
  --set-env-vars "SERVICE_NAME=${SERVICE_NAME},SERVICE_VERSION=${SERVICE_VERSION},PLATFORM_ENV=${ENV}" \
  --set-secrets "RUVECTOR_SERVICE_URL=ruvector-service-url:latest,RUVECTOR_API_KEY=ruvector-api-key:latest,TELEMETRY_ENDPOINT=telemetry-endpoint:latest" \
  --service-account "llm-shield-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --labels "service=llm-shield,env=${ENV},version=${SERVICE_VERSION}"

# Step 5: Verify deployment
echo ""
echo "[5/5] Verifying deployment..."
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}-${ENV}" \
  --region="$REGION" \
  --format='value(status.url)')

echo "Service URL: $SERVICE_URL"

echo ""
echo "Testing /health endpoint..."
if curl -sf "${SERVICE_URL}/health" > /dev/null; then
  echo "✓ Health check passed"
else
  echo "✗ Health check failed"
  exit 1
fi

echo ""
echo "Testing /info endpoint..."
curl -s "${SERVICE_URL}/info" | head -50

echo ""
echo "============================================================"
echo "Deployment Complete!"
echo "============================================================"
echo "Service URL: $SERVICE_URL"
echo ""
echo "Agent Endpoints:"
echo "  POST ${SERVICE_URL}/agents/prompt-injection/detect"
echo "  POST ${SERVICE_URL}/agents/pii/detect"
echo "  POST ${SERVICE_URL}/agents/redaction/detect"
echo "  POST ${SERVICE_URL}/agents/secrets/detect"
echo "  POST ${SERVICE_URL}/agents/toxicity/detect"
echo "  POST ${SERVICE_URL}/agents/safety/detect"
echo "  POST ${SERVICE_URL}/agents/moderation/detect"
echo "  POST ${SERVICE_URL}/agents/abuse/detect"
echo "  POST ${SERVICE_URL}/agents/credentials/detect"
echo "============================================================"

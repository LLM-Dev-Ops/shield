#!/bin/bash
# Data Redaction Agent - GCP Deployment Script
# LLM-Shield
#
# Usage:
#   ./deploy.sh [environment] [options]
#
# Environments: dev, staging, production
# Options:
#   --function    Deploy as Cloud Function (default)
#   --run         Deploy as Cloud Run service
#   --dry-run     Show what would be deployed without deploying

set -euo pipefail

# Configuration
AGENT_NAME="data-redaction-agent"
AGENT_VERSION="1.0.0"
REGION="${GCP_REGION:-us-central1}"
PROJECT="${GCP_PROJECT:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
ENVIRONMENT="${1:-dev}"
DEPLOY_TYPE="function"
DRY_RUN=false

shift || true
while [[ $# -gt 0 ]]; do
  case $1 in
    --function) DEPLOY_TYPE="function"; shift ;;
    --run) DEPLOY_TYPE="run"; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
  esac
done

# Validate environment
case $ENVIRONMENT in
  dev|staging|production) ;;
  *) echo -e "${RED}Invalid environment: $ENVIRONMENT${NC}"; exit 1 ;;
esac

# Check prerequisites
if [[ -z "$PROJECT" ]]; then
  echo -e "${RED}Error: GCP_PROJECT environment variable not set${NC}"
  exit 1
fi

if ! command -v gcloud &> /dev/null; then
  echo -e "${RED}Error: gcloud CLI not found${NC}"
  exit 1
fi

echo -e "${GREEN}🔒 Deploying Data Redaction Agent${NC}"
echo "  Environment: $ENVIRONMENT"
echo "  Project: $PROJECT"
echo "  Region: $REGION"
echo "  Deploy Type: $DEPLOY_TYPE"
echo ""

# Build the agent
echo -e "${YELLOW}Building agent...${NC}"
cd "$(dirname "$0")/.."
npm ci
npm run build

# Environment-specific configuration
case $ENVIRONMENT in
  dev)
    RUVECTOR_URL="http://ruvector-service-dev.internal:8080"
    MIN_INSTANCES=0
    MAX_INSTANCES=10
    ;;
  staging)
    RUVECTOR_URL="http://ruvector-service-staging.internal:8080"
    MIN_INSTANCES=1
    MAX_INSTANCES=50
    ;;
  production)
    RUVECTOR_URL="http://ruvector-service.internal:8080"
    MIN_INSTANCES=2
    MAX_INSTANCES=100
    ;;
esac

if $DRY_RUN; then
  echo -e "${YELLOW}[DRY RUN] Would deploy with:${NC}"
  echo "  RUVECTOR_URL: $RUVECTOR_URL"
  echo "  MIN_INSTANCES: $MIN_INSTANCES"
  echo "  MAX_INSTANCES: $MAX_INSTANCES"
  exit 0
fi

# Deploy based on type
if [[ "$DEPLOY_TYPE" == "function" ]]; then
  echo -e "${YELLOW}Deploying as Cloud Function...${NC}"

  gcloud functions deploy "$AGENT_NAME" \
    --project="$PROJECT" \
    --region="$REGION" \
    --runtime=nodejs20 \
    --entry-point=handleRequest \
    --trigger-http \
    --memory=256MB \
    --timeout=30s \
    --min-instances="$MIN_INSTANCES" \
    --max-instances="$MAX_INSTANCES" \
    --set-env-vars="NODE_ENV=production,RUVECTOR_SERVICE_URL=$RUVECTOR_URL,TELEMETRY_ENABLED=true" \
    --set-secrets="RUVECTOR_API_KEY=ruvector-api-key:latest" \
    --ingress-settings=internal-and-gclb \
    --no-allow-unauthenticated \
    --service-account="llm-shield-agent@$PROJECT.iam.gserviceaccount.com" \
    --source=.

else
  echo -e "${YELLOW}Deploying as Cloud Run service...${NC}"

  # Build container image
  IMAGE="gcr.io/$PROJECT/$AGENT_NAME:$AGENT_VERSION"

  echo "Building container image: $IMAGE"
  docker build -t "$IMAGE" -f deploy/Dockerfile .

  echo "Pushing to GCR..."
  docker push "$IMAGE"

  echo "Deploying to Cloud Run..."
  gcloud run deploy "$AGENT_NAME" \
    --project="$PROJECT" \
    --region="$REGION" \
    --image="$IMAGE" \
    --platform=managed \
    --memory=512Mi \
    --cpu=1 \
    --timeout=30s \
    --min-instances="$MIN_INSTANCES" \
    --max-instances="$MAX_INSTANCES" \
    --set-env-vars="NODE_ENV=production,RUVECTOR_SERVICE_URL=$RUVECTOR_URL,TELEMETRY_ENABLED=true" \
    --set-secrets="RUVECTOR_API_KEY=ruvector-api-key:latest" \
    --ingress=internal-and-cloud-load-balancing \
    --no-allow-unauthenticated \
    --service-account="llm-shield-agent@$PROJECT.iam.gserviceaccount.com"
fi

echo -e "${GREEN}✓ Deployment complete!${NC}"

# Get the URL
if [[ "$DEPLOY_TYPE" == "function" ]]; then
  URL=$(gcloud functions describe "$AGENT_NAME" --project="$PROJECT" --region="$REGION" --format='value(httpsTrigger.url)')
else
  URL=$(gcloud run services describe "$AGENT_NAME" --project="$PROJECT" --region="$REGION" --format='value(status.url)')
fi

echo ""
echo "Agent URL: $URL"
echo ""
echo "Test with:"
echo "  curl -X POST '$URL' \\"
echo "    -H 'Authorization: Bearer \$(gcloud auth print-identity-token)' \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"content\": \"test@example.com\", \"context\": {\"execution_ref\": \"test\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"content_source\": \"user_input\"}}'"

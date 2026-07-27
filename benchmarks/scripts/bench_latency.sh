#!/bin/bash
##############################################################################
# Latency Benchmark Script
#
# Measures end-to-end latency for scanning operations across 4 scenarios:
# - Scenario 1A: BanSubstrings (string matching) - Target: <1ms
# - Scenario 1B: Regex scanning (10 patterns) - Target: 1-3ms
# - Scenario 1C: Secret detection (40+ patterns) - Target: 5-10ms
# - Scenario 1D: PromptInjection (heuristic) - Target: 5-10ms
#
# Collects 1000 iterations per scenario and computes:
# - Mean, median, std deviation
# - p50, p95, p99 latencies
#
# Output: latency_results.csv
##############################################################################

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_ROOT="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$BENCHMARK_ROOT")"
DATA_DIR="$BENCHMARK_ROOT/data"
RESULTS_DIR="$BENCHMARK_ROOT/results"
PYTHON_RUNNER="$SCRIPT_DIR/simulate_latency_benchmark.py"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create results directory if it doesn't exist
mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  LLM Shield Latency Benchmark${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo "Data Directory: $DATA_DIR"
echo "Results Directory: $RESULTS_DIR"
echo ""

# Check if test data exists
if [ ! -f "$DATA_DIR/test_prompts.json" ]; then
    echo -e "${YELLOW}Test data not found. Generating...${NC}"
    python3 "$SCRIPT_DIR/generate_test_data.py"
fi

# Run Python benchmark runner
echo -e "${BLUE}Running latency benchmarks...${NC}"
echo ""

python3 "$PYTHON_RUNNER"
EXIT_CODE=$?

# Check if results were generated
if [ -f "$RESULTS_DIR/latency_results.csv" ]; then
    echo ""
    echo -e "${GREEN}✓ Benchmark completed successfully!${NC}"
    echo -e "${GREEN}Results saved to: $RESULTS_DIR/latency_results.csv${NC}"
    echo ""

    # Display summary table
    echo -e "${BLUE}Results Table:${NC}"
    echo "----------------------------------------"
    cat "$RESULTS_DIR/latency_results.csv" | column -t -s ','
    echo "----------------------------------------"
else
    echo -e "${RED}✗ Benchmark failed - results not generated${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}Done!${NC}"

exit $EXIT_CODE

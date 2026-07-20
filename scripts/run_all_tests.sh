#!/bin/bash
# Kylin Agent — Full Test Suite Runner (#22)
set -e

echo "=== Kylin Agent Full Test Suite ==="
echo "Date: $(date -Iseconds)"
echo "Python: $(python3 --version 2>&1)"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/../backend"
cd "$BACKEND_DIR"

# Run all tests
python3 -m pytest tests/ -v --tb=short 2>&1 | tee ../test-output.txt

# Count results
TOTAL=$(grep -cE "(PASSED|FAILED|ERROR)" ../test-output.txt 2>/dev/null || true)
PASSED=$(grep -c "PASSED" ../test-output.txt 2>/dev/null || true)
FAILED=$(grep -c "FAILED" ../test-output.txt 2>/dev/null || true)
TOTAL=${TOTAL:-0}
PASSED=${PASSED:-0}
FAILED=${FAILED:-0}

echo ""
echo "========================================="
echo "Total: $TOTAL | Passed: $PASSED | Failed: $FAILED"
echo "========================================="

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi

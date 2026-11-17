#!/usr/bin/env bash
# Runs every formal-verification artifact. Z3 proofs need `pip install z3-solver`
# (set PYTHON to an interpreter that has it); the model checkers need only node.
set -euo pipefail
cd "$(dirname "$0")"
PYTHON="${PYTHON:-python3}"
if "$PYTHON" -c "import z3" 2>/dev/null; then "$PYTHON" proofs.py
else echo "SKIPPED proofs.py (z3-solver not installed)"; fi
for c in check_tcp_utils check_packet check_pacer check_udp check_rate_limiter check_retransmission check_ooo; do
  node "$c.js"
done
echo "ALL VERIFICATION PASSED"

#!/usr/bin/env bash
# Gramine-direct functional regression for the independent TEE+CBC PoC.
# Direct mode is a functional simulation ONLY; it is not evidence of SGX
# security or performance.  Real gramine-sgx hardware validation is TODO.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DATA=${TEE_CBC_TEST_DATA:-/tmp/tee-cbc-direct-data}
OUT=${TEE_CBC_OUT:-/tmp/tee-cbc-direct-build}
BUILD_DIR=${TEE_CBC_BUILD_DIR:-"$ROOT/build/scalable"}
BIN="$BUILD_DIR/soci_cbc_plaintext_benchmark"

rm -rf "$DATA" "$OUT"
mkdir -p "$DATA"

# CBC Exact path: the per-row cheapest selection violates the ratio
# threshold, so the cheapest fast path is infeasible and CBC must solve.
cat > "$DATA/costs_exact.tsv" <<'EOF'
10	12	10.1
11	13	11.1
12	14	12.1
10	12	10.1
11	13	11.1
12	14	12.1
EOF
# Cheapest fast path: the per-row cheapest selection already satisfies the
# ratio (lhs 3 >= rhs 1 at T=0.5), so CBC is never invoked.
cat > "$DATA/costs_fast.tsv" <<'EOF'
1	20	10
2	20	10
50	60	1
EOF

assert_no_residue() {
  # No LP model / CBC solution / solver log may survive on the host side,
  # neither beside the manifests nor in the host-visible input directory.
  if find "$DATA" "$OUT" -type f \( -name '*.lp' -o -name '*.sol' -o -name '*.log' \) | grep -q .; then
    echo "sensitive residue found under $DATA or $OUT" >&2; exit 1
  fi
  if compgen -G "/tmp/soci_cbc_*" > /dev/null; then
    echo "sensitive residue found in host /tmp" >&2; exit 1
  fi
}

json_check() {
  python3 -c 'import json,sys
d = json.loads(sys.argv[1])
assert d["optimality_status"] == sys.argv[2], d
print(d)' "$1" "$2"
}

echo "== build direct + strict SGX manifests; sign SGX with a throwaway key"
openssl genrsa -3 -out "$OUT-signing-key.pem" 3072 2>/dev/null
TEE_CBC_BUILD_SGX=1 SGX_SIGNING_KEY="$OUT-signing-key.pem" \
  TEE_CBC_DATA_DIR="$DATA" TEE_CBC_OUT="$OUT" \
  "$ROOT/tee_cbc/build_tee_cbc.sh" "$BUILD_DIR"
# The strict manifest must render and measure offline (fail-closed: a
# missing trusted file would abort gramine-sgx-sign).
test -f "$OUT/sgx/soci_cbc_plaintext_benchmark.manifest.sgx"
! grep -q allow_all_but_log "$OUT/sgx/soci_cbc_plaintext_benchmark.manifest"
grep -q 'file_check_policy = "strict"' "$OUT/sgx/soci_cbc_plaintext_benchmark.manifest"

echo "== host-level cleanup checks (no Gramine)"
TMP=$(mktemp -d)
json_check "$(SOCI_CBC_TMPDIR="$TMP" "$BIN" "$DATA/costs_exact.tsv" 6 0.5 60)" optimal_verified
[[ -z $(find "$TMP" -type f -print -quit) ]]
json_check "$(SOCI_CBC_TMPDIR="$TMP" "$BIN" "$DATA/costs_fast.tsv" 3 0.5 60)" cheapest_global_optimum
[[ -z $(find "$TMP" -type f -print -quit) ]]
# Solver failure path (rc != 0): timeout JSON, temp files removed.
json_check "$(SOCI_CBC_TMPDIR="$TMP" SOCI_CBC_COMMAND=/bin/false "$BIN" "$DATA/costs_exact.tsv" 6 0.5 60)" timeout
[[ -z $(find "$TMP" -type f -print -quit) ]]
# Exception path (empty CBC output): nonzero exit, temp files removed.
if SOCI_CBC_TMPDIR="$TMP" SOCI_CBC_COMMAND=/bin/true "$BIN" "$DATA/costs_exact.tsv" 6 0.5 60 2>/dev/null; then
  echo "expected failure for empty CBC solution" >&2; exit 1
fi
[[ -z $(find "$TMP" -type f -print -quit) ]]
rm -rf "$TMP"

echo "== gramine-direct: CBC Exact path"
cp "$DATA/costs_exact.tsv" "$DATA/costs.tsv"
result=$(TEE_CBC_DATA_DIR="$DATA" TEE_CBC_OUT="$OUT" \
  "$ROOT/tee_cbc/run_tee_cbc.sh" direct 6 0.5 60)
python3 -c 'import json,sys
d = json.loads(sys.argv[1])
assert d["optimality_status"] == "optimal_verified", d
assert d["total_cost"] > 0 and len(d["solution"]) == 6, d
print(d)' "$result"
assert_no_residue

echo "== gramine-direct: cheapest fast path"
cp "$DATA/costs_fast.tsv" "$DATA/costs.tsv"
result=$(TEE_CBC_DATA_DIR="$DATA" TEE_CBC_OUT="$OUT" \
  "$ROOT/tee_cbc/run_tee_cbc.sh" direct 3 0.5 60)
python3 -c 'import json,sys
d = json.loads(sys.argv[1])
assert d["optimality_status"] == "cheapest_global_optimum", d
assert d["solution"] == [1, 1, 3], d
print(d)' "$result"
assert_no_residue

echo "== gramine-direct: solver failure path cleans up"
cp "$DATA/costs_exact.tsv" "$DATA/costs.tsv"
result=$(SOCI_CBC_COMMAND=/bin/false TEE_CBC_DATA_DIR="$DATA" TEE_CBC_OUT="$OUT" \
  "$ROOT/tee_cbc/run_tee_cbc.sh" direct 6 0.5 60)
json_check "$result" timeout
assert_no_residue

echo "== fail-closed probe: undeclared host file must be unreadable"
# /usr/bin/ls sits under a mounted path but is NOT in the strict trusted
# list; opening it as input must be denied by the file-check policy.
if gramine-direct "$OUT/direct/soci_cbc_plaintext_benchmark" /usr/bin/ls 6 0.5 5 2>/dev/null; then
  echo "undeclared file access unexpectedly succeeded" >&2; exit 1
fi
assert_no_residue

echo "tee_cbc direct regression passed"

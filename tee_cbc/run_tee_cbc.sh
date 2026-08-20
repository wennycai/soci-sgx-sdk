#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT=${TEE_CBC_OUT:-"$ROOT/build/tee_cbc"}
MODE=${1:?usage: run_tee_cbc.sh native|direct|sgx ROWS THRESHOLD [TIMEOUT]}
ROWS=${2:?missing rows}; THRESHOLD=${3:?missing threshold}; TIMEOUT=${4:-60}

# The /input and /work mounts are baked into the manifest when
# build_tee_cbc.sh renders it, so they cannot be redirected per run.  The build
# records them here and the native control reads exactly the same files, which
# is what makes the native-vs-Gramine comparison apples to apples.
[[ -f "$OUT/env" ]] && . "$OUT/env"
DATA_DIR=${TEE_CBC_DATA_DIR:-"$OUT/data"}
WORK_DIR=${TEE_CBC_WORK_DIR:-"$OUT/work"}

# Native control: the same benchmark binary on plain Linux, no Gramine.  It is
# the performance baseline only and makes no confidentiality claim, but its CBC
# intermediates must NOT land in "$WORK_DIR": that directory is the host-side
# backing store of the Gramine *encrypted* /work mount, and dropping plaintext
# .lp/.sol/.log files into it would both corrupt the mount's file set and make
# the host-side "no plaintext residue" check meaningless.  Native therefore gets
# its own sibling directory (the benchmark still removes the files on every
# exit path).
if [[ "$MODE" == native ]]; then
  BIN="$OUT/native/soci_cbc_plaintext_benchmark"
  [[ -x "$BIN" ]] || { echo "run build_tee_cbc.sh first" >&2; exit 2; }
  NATIVE_WORK_DIR=${TEE_CBC_NATIVE_WORK_DIR:-"$OUT/native-work"}
  mkdir -p "$NATIVE_WORK_DIR"
  exec env SOCI_CBC_TMPDIR="$NATIVE_WORK_DIR" "$BIN" \
    "$DATA_DIR/costs.tsv" "$ROWS" "$THRESHOLD" "$TIMEOUT"
fi

MANIFEST="$OUT/$MODE/soci_cbc_plaintext_benchmark.manifest"
[[ -f "$MANIFEST" ]] || { echo "run build_tee_cbc.sh first" >&2; exit 2; }

# CBC's own "seconds" limit is unusable under Gramine and must be disabled with
# TIMEOUT=0; the caller bounds the run from outside instead.  CBC derives the
# limit from CoinCpuTime(), which Gramine does not report relative to the
# process, so any finite limit reads as already exhausted before the solve
# starts: CBC abandons preprocessing and writes its root relaxation under an
# "Integer infeasible" header.  Measured on the 6-row regression instance, that
# is 10/10 runs with `seconds 60` against 10/10 correct without it.  This is
# rejected loudly rather than silently overridden, because the failure mode it
# guards against is a *wrong answer*, not a slow one.
if [[ "$TIMEOUT" != 0 ]]; then
  echo "$MODE mode requires TIMEOUT=0: CBC's internal time limit is not" >&2
  echo "usable under Gramine and yields bogus infeasibility. Bound the run" >&2
  echo "externally instead (see tee_cbc/README.md)." >&2
  exit 2
fi

# The host sees only public dimensions/threshold and the final JSON.  Costs
# are read from /input inside Gramine; CBC's LP/solution/log files stay on
# the in-Gramine encrypted mount at /work (set via loader.env in the
# manifest), so the host only ever sees ciphertext and the benchmark removes
# the files on every exit path.
if [[ "$MODE" == sgx ]]; then
  exec gramine-sgx "$OUT/$MODE/soci_cbc_plaintext_benchmark" \
    /input/costs.tsv "$ROWS" "$THRESHOLD" "$TIMEOUT"
fi
exec gramine-direct "$OUT/$MODE/soci_cbc_plaintext_benchmark" \
  /input/costs.tsv "$ROWS" "$THRESHOLD" "$TIMEOUT"

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
ctest --preset off-debug

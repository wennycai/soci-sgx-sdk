#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
CMAKE_PRESET_NAME=off-debug cmake --preset off-debug
cmake --build --preset off-debug

#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"
build="$repo/build/off-debug"
classes="$build/demo-java"
find_java_tool() {
  local tool="$1" candidate
  if command -v "$tool" >/dev/null 2>&1; then
    command -v "$tool"
    return
  fi
  if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/$tool" ]]; then
    printf '%s\n' "$JAVA_HOME/bin/$tool"
    return
  fi
  for candidate in /usr/lib/jvm/*/bin/"$tool"; do
    [[ -x "$candidate" ]] && { printf '%s\n' "$candidate"; return; }
  done
  echo "Missing Java JDK tool '$tool'. Install a JDK, for example:" >&2
  echo "  sudo apt update && sudo apt install openjdk-11-jdk" >&2
  exit 1
}
javac_bin="$(find_java_tool javac)"
java_bin="$(find_java_tool java)"
port="${1:-8080}"
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$port$"; then
  echo "Port $port is already in use." >&2
  echo "Stop the existing service, or choose another port:" >&2
  echo "  ./examples/optimization-demo/run_off_demo.sh $((port + 1))" >&2
  exit 1
fi
cache="$build/CMakeCache.txt"
if [[ -f "$cache" ]]; then
  cached_source="$(sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' "$cache")"
  if [[ -n "$cached_source" && "$cached_source" != "$repo" ]]; then
    echo "Removing relocated CMake cache: $cached_source -> $repo"
    cmake -E remove_directory "$build"
  fi
fi
CMAKE_PRESET_NAME=off-debug cmake --preset off-debug -DSOCI_BUILD_JAVA=ON -DSOCI_ENABLE_EXPERIMENTAL_PROTOCOLS=ON
cmake --build --preset off-debug -j2
mkdir -p "$classes"
"$javac_bin" -d "$classes" \
  $(find "$repo/bindings/java/src/main/java" "$repo/examples/optimization-demo/java" -name '*.java' -print)
LD_LIBRARY_PATH="$build${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  "$java_bin" -Djava.library.path="$build" -cp "$classes" com.soci.demo.SociDemoServer \
  "$repo/examples/optimization-demo" "$port" OFF "$repo/runtime/off/demo"

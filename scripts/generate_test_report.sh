#!/usr/bin/env bash
# generate_test_report.sh — 运行可运行的测试/基准并把所有产物汇总成报告。
#
# 用法:
#   ./scripts/generate_test_report.sh                     # 跑可运行项 + 汇总
#   ./scripts/generate_test_report.sh --modes off         # 仅 OFF
#   ./scripts/generate_test_report.sh --collect-only      # 不执行，仅汇总已有产物
#   ./scripts/generate_test_report.sh --no-benchmark      # 跳过性能基准
#   ./scripts/generate_test_report.sh --output results    # 报告输出目录
#
# 三种模式按可用性优雅降级:
#   OFF — 本地，无需 SGX；build_off + ctest(-T Test) + run_benchmark
#   SIM — 本地有 SGX SDK 则原生跑，否则经 docker/compose.sim.yaml(容器内装 SDK)
#   HW  — 需要 /dev/sgx_enclave；有则经 dist/compose.hw.deploy.yaml，否则跳过
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

MODES="off,sim,hw"
COLLECT_ONLY=0
RUN_BENCHMARK=1
OUTPUT_DIR="results"
NO_NATIVE=0

usage() {
  cat <<'EOF'
Usage: ./scripts/generate_test_report.sh [options]

Options:
  --modes <csv>       要执行的模式，逗号分隔 (off,sim,hw)，默认全部
  --collect-only      不执行任何构建/测试，仅汇总已有产物生成报告
  --no-benchmark      跳过性能基准测试
  --no-native         强制 SIM/HW 走 dist 镜像，不使用本机 SGX SDK 原生构建
                      (镜像部署、无源码的内网服务器用；等价于 SOCI_NO_NATIVE=1)
  --output <dir>      报告输出目录 (默认 results)
  -h, --help          显示本帮助

说明:
  - 默认会实际执行可运行的测试与基准；SIM 优先用已加载的 dist 镜像(离线、无需 SGX
    设备)，无 dist 镜像时回退到 compose.sim.yaml(需联网下载 SGX SDK)。仅想快速生成
    报告可加 --collect-only 或 --modes off。
  - HW 模式(需 SGX 设备)除单镜像基准(KeyGen+FULL_DECRYPT)外，还自动跑 CP/CSP 双镜像
    协议基准(Encrypt/SADD/ScalarMul/SMUL/SCMP/SABS/SDIV 等，需 cp/csp 镜像)；
    --no-benchmark 跳过全部基准。
  - 任何已执行的步骤失败 -> 脚本以非 0 退出；全跳过或全过 -> 0。
  - 报告产物: <output>/test-report.md, <output>/test-report.json
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --modes)        MODES="${2:-}"; shift 2 ;;
    --collect-only) COLLECT_ONLY=1; shift ;;
    --no-benchmark) RUN_BENCHMARK=0; shift ;;
    --no-native)    NO_NATIVE=1; shift ;;
    --output)       OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help)      usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$MODES" ]] || { echo "--modes 不能为空" >&2; exit 2; }
[[ -n "$OUTPUT_DIR" ]] || { echo "--output 不能为空" >&2; exit 2; }
[[ "${SOCI_NO_NATIVE:-0}" == "1" ]] && NO_NATIVE=1

mkdir -p "$OUTPUT_DIR/report-artifacts"
ARTIFACTS_DIR="$OUTPUT_DIR/report-artifacts"
if (( COLLECT_ONLY )); then
  echo "==> collect-only: 复用 results/ 已有产物重新渲染（不执行构建/测试，不覆盖 env/steps/skips）"
else
  : > "$ARTIFACTS_DIR/steps.tsv"
  : > "$ARTIFACTS_DIR/skips.tsv"
fi
SGX_SDK="${SGX_SDK:-/opt/intel/sgxsdk}"

# ---- helpers ----------------------------------------------------------------

# resolve_compose: 优先 docker-compose，其次 `docker compose` 插件
resolve_compose() {
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
  elif docker compose version >/dev/null 2>&1; then
    echo "docker compose"
  else
    echo ""
  fi
}

# run_step <mode> <step> <cmd-string>
# 用 bash -lc 执行 <cmd-string>，捕获合并输出与退出码，永不让脚本在此中止。
run_step() {
  local mode="$1" step="$2" cmd="$3"
  local log="$ARTIFACTS_DIR/${mode}-${step}.log"
  {
    echo "=== $mode / $step ==="
    echo "=== cmd: $cmd ==="
    echo "=== start ==="
  } > "$log"
  local status
  if bash -lc "$cmd" >>"$log" 2>&1; then
    status=0
  else
    status=$?
  fi
  echo "=== end (exit $status) ===" >> "$log"
  echo "$status" > "$ARTIFACTS_DIR/${mode}-${step}.status"
  printf '%s\t%s\t%s\t%s\n' "$mode" "$step" "$status" "$log" >> "$ARTIFACTS_DIR/steps.tsv"
  if (( status == 0 )); then
    echo "  [OK]   $mode/$step"
  else
    echo "  [FAIL] $mode/$step (exit $status; 详见 $log)"
  fi
  return 0
}

record_skip() {
  local mode="$1" reason="$2"
  printf '%s\t%s\n' "$mode" "$reason" >> "$ARTIFACTS_DIR/skips.tsv"
  echo "  [SKIP] $mode: $reason"
}

# probe_env: 探测实际环境，写入 env.txt (key=value)
probe_env() {
  local f="$ARTIFACTS_DIR/env.txt"
  : > "$f"
  _emit() { printf '%s=%s\n' "$1" "$2" >> "$f"; }
  _emit host "$(hostname 2>/dev/null || echo unknown)"
  _emit uname "$(uname -a 2>/dev/null || echo unknown)"
  _emit date_iso "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
  _emit nproc "$(nproc 2>/dev/null || echo unknown)"
  _emit os_release "$( (grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"') || echo unknown)"
  _emit gcc_version "$( (gcc --version 2>/dev/null | head -1) || echo 'not found')"
  _emit gcc11_path "$(command -v gcc-11 2>/dev/null || echo 'not found')"
  _emit gpp_version "$( (g++ --version 2>/dev/null | head -1) || echo 'not found')"
  _emit gpp11_path "$(command -v g++-11 2>/dev/null || echo 'not found')"
  _emit cmake_version "$( (cmake --version 2>/dev/null | head -1) || echo 'not found')"
  _emit ctest_version "$( (ctest --version 2>/dev/null) || echo 'not found')"
  _emit python3_version "$( (python3 --version 2>/dev/null) || echo 'not found')"
  _emit openssl_version "$( (openssl version 2>/dev/null) || echo 'not found')"
  _emit java_version "$( (java -version 2>&1 | head -1) || echo 'not found')"
  _emit docker_version "$( (docker --version 2>/dev/null) || echo 'not found')"
  _emit docker_compose "$(resolve_compose)"
  _emit sgx_sdk_env "$SGX_SDK"
  if [[ -x "$SGX_SDK/bin/x64/sgx_edger8r" ]]; then
    _emit sgx_sdk_present yes
  else
    _emit sgx_sdk_present no
  fi
  local dev=""
  [[ -e /dev/sgx_enclave ]] && dev="/dev/sgx_enclave"
  [[ -e /dev/sgx/enclave ]] && dev="${dev:-/dev/sgx/enclave}"
  _emit sgx_enclave_device "${dev:-none}"
  [[ -e /dev/sgx_provision ]] && _emit sgx_provision_device /dev/sgx_provision || _emit sgx_provision_device none
  if grep -qw sgx /proc/cpuinfo 2>/dev/null; then _emit cpu_sgx_flag yes; else _emit cpu_sgx_flag no; fi
  # dist 打包镜像信息
  if [[ -f dist/soci-sgx-hw-2.26.image-id.txt ]]; then
    _emit dist_image_id "$(cat dist/soci-sgx-hw-2.26.image-id.txt)"
  else
    _emit dist_image_id "none"
  fi
  if [[ -f dist/soci-sgx-hw-2.26.tar.gz.sha256 ]]; then
    _emit dist_archive_sha256 "$(cat dist/soci-sgx-hw-2.26.tar.gz.sha256)"
    if [[ -f dist/soci-sgx-hw-2.26.tar.gz ]] && command -v sha256sum >/dev/null 2>&1; then
      if (cd dist && sha256sum -c soci-sgx-hw-2.26.tar.gz.sha256) >/dev/null 2>&1; then
        _emit dist_sha256_verify ok
      else
        _emit dist_sha256_verify failed
      fi
    else
      _emit dist_sha256_verify skipped
    fi
  else
    _emit dist_archive_sha256 none
    _emit dist_sha256_verify skipped
  fi
  # 已加载的 docker 镜像 (仅 soci-sgx 相关，repo:tag@id)
  if command -v docker >/dev/null 2>&1; then
    _emit docker_images_soci "$(docker images --format '{{.Repository}}:{{.Tag}}@{{.ID}}' 2>/dev/null | grep -i 'soci-sgx' | tr '\n' ',' || echo none)"
  else
    _emit docker_images_soci none
  fi
  # git
  if command -v git >/dev/null 2>&1 && git -C "$PROJECT_DIR" rev-parse HEAD >/dev/null 2>&1; then
    _emit git_commit "$(git -C "$PROJECT_DIR" rev-parse --short HEAD)"
    _emit git_branch "$(git -C "$PROJECT_DIR" rev-parse --abbrev-ref HEAD)"
  else
    _emit git_commit none
    _emit git_branch none
  fi
}

# clean_stale_cache <build_dir>: 若该 preset 的 CMake 缓存指向其它源目录则删除。
# 项目被移动/复制后缓存仍指向旧路径，cmake 会拒绝复用；这类缓存从当前位置永远不可用，
# 删除是安全且必要的。仅清理即将本地配置的 preset 目录，避免误碰 docker 生成的 root 目录。
clean_stale_cache() {
  local bdir="$1" cache cached_src
  cache="$bdir/CMakeCache.txt"
  [[ -f "$cache" ]] || return 0
  cached_src=$(grep -m1 '^CMAKE_HOME_DIRECTORY:' "$cache" 2>/dev/null | cut -d= -f2- || true)
  if [[ -n "$cached_src" && "$cached_src" != "$PROJECT_DIR" ]]; then
    echo "  [清理] 过期 CMake 缓存: $bdir (曾指向 $cached_src)"
    rm -rf "$bdir" 2>/dev/null || {
      echo "  [warn] 无法删除 $bdir (可能为 root 所属)；尝试仅删除 CMakeCache.txt"
      rm -f "$cache" 2>/dev/null || true
    }
  fi
}

# ---- per-mode runners -------------------------------------------------------

run_off() {
  echo "==> OFF 模式 (本地，无需 SGX)"
  if (( COLLECT_ONLY )); then record_skip off "collect-only"; return 0; fi
  clean_stale_cache build/off-debug
  run_step off build 'CMAKE_PRESET_NAME=off-debug cmake --preset off-debug && cmake --build --preset off-debug'
  # ctest 默认输出含 "N/M Test #K: name ... Passed" 逐项行，渲染器据步骤日志解析
  run_step off test 'ctest --preset off-debug'
  if (( RUN_BENCHMARK )); then
    clean_stale_cache build/off-benchmark
    run_step off benchmark 'scripts/run_benchmark.sh 3072 50'
  fi
}

run_sim() {
  echo "==> SIM 模式"
  if (( COLLECT_ONLY )); then record_skip sim "collect-only"; return 0; fi
  # 1) 本地有 SGX SDK -> 原生 SIM  (--no-native / SOCI_NO_NATIVE=1 时跳过，改用镜像)
  if (( ! NO_NATIVE )) && [[ -x "$SGX_SDK/bin/x64/sgx_edger8r" ]]; then
    echo "  本地检测到 SGX SDK -> 原生 SIM"
    clean_stale_cache build/sim-release
    run_step sim build 'CMAKE_PRESET_NAME=sim-release cmake --preset sim-release && cmake --build --preset sim-release'
    run_step sim test "export LD_LIBRARY_PATH=\"$SGX_SDK/lib64\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\"; ctest --preset sim-release"
    if (( RUN_BENCHMARK )); then
      run_step sim benchmark 'scripts/run_sim_benchmark.sh 100 30 10 5'
    fi
    return 0
  fi
  # 2) 已加载 dist 镜像 -> 用它跑 SIM (镜像内含 SGX SDK 2.26 + 固定工具链 gcc-11/cmake +
  #    可信 GMP /opt/soci/gmp-sgx；离线、无需 SGX 设备，比 compose.sim.yaml 快得多)
  local hw_image="${SOCI_IMAGE:-soci-sgx-hw:2.26}"
  if command -v docker >/dev/null 2>&1 && docker image inspect "$hw_image" >/dev/null 2>&1; then
    if (( NO_NATIVE )); then
      echo "  --no-native: 跳过原生构建，使用已加载的 dist 镜像 $hw_image 运行 SIM (离线，无需 SGX 设备)"
    else
      echo "  无本地 SGX SDK；使用已加载的 dist 镜像 $hw_image 运行 SIM (离线，无需 SGX 设备)"
    fi
    local results_vol="${PROJECT_DIR}/results:/workspace/results"
    local bench_cmd=""
    if (( RUN_BENCHMARK )); then
      bench_cmd='LD_LIBRARY_PATH=/opt/intel/sgxsdk/lib64 ./build/sim-release/soci_sgx_crypto_benchmark ./build/sim-release/soci_provisioning_enclave.signed.so 100 30 10 5 > /workspace/results/benchmark-sim-3072.json'
    fi
    # 单次容器内完成 配置+构建+测试(+基准)，避免重复构建(容器即用即弃)；挂载 results 回收基准 JSON
    run_step sim build-test "docker run --rm --entrypoint bash -v \"$results_vol\" $hw_image -lc \"set -e; cd /workspace; CMAKE_PRESET_NAME=sim-release cmake --preset sim-release -DGMP_SGX_ROOT=/opt/soci/gmp-sgx && cmake --build --preset sim-release && LD_LIBRARY_PATH=/opt/intel/sgxsdk/lib64 ctest --preset sim-release${bench_cmd:+ && $bench_cmd}\""
    return 0
  fi
  # 3) 回退: compose.sim.yaml (从源码构建含 SDK 的镜像，需联网下载 Intel SGX SDK)
  local dc; dc="$(resolve_compose)"
  if [[ -z "$dc" ]]; then
    record_skip sim "无本地 SGX SDK、无 dist 镜像、无 docker；无法运行 SIM"
    return 0
  fi
  echo "  无本地 SGX SDK 且无 dist 镜像 -> 经 docker compose (docker/compose.sim.yaml) 从源码构建"
  echo "  注意: 首次构建会下载 Intel SGX SDK，耗时较长且需联网。"
  local results_vol2="${PROJECT_DIR}/results:/workspace/results"
  run_step sim build-test "$dc -f docker/compose.sim.yaml build"
  run_step sim test "$dc -f docker/compose.sim.yaml run --rm test bash -lc \"scripts/build_sim.sh && ctest --preset sim-release\""
  if (( RUN_BENCHMARK )); then
    run_step sim benchmark "$dc -f docker/compose.sim.yaml run --rm -v \"$results_vol2\" test bash -lc \"scripts/run_sim_benchmark.sh 100 30 10 5\""
  fi
}

run_hw() {
  echo "==> HW 模式"
  if (( COLLECT_ONLY )); then record_skip hw "collect-only"; return 0; fi
  local have_device=0
  [[ -e /dev/sgx_enclave || -e /dev/sgx/enclave ]] && have_device=1
  if (( ! have_device )); then
    record_skip hw "宿主无 /dev/sgx_enclave（或 /dev/sgx/enclave）；HW Enclave 测试需要 SGX 硬件"
    return 0
  fi
  if (( ! NO_NATIVE )) && [[ -x "$SGX_SDK/bin/x64/sgx_edger8r" ]]; then
    echo "  本地检测到 SGX SDK 与设备 -> 原生 HW"
    run_step hw check 'scripts/check_sgx_host.sh'
    clean_stale_cache build/hw-release
    run_step hw build 'CMAKE_PRESET_NAME=hw-release cmake --preset hw-release && cmake --build --preset hw-release'
    run_step hw test 'ctest --preset hw-release'
    if (( RUN_BENCHMARK )); then
      run_step hw benchmark "export LD_LIBRARY_PATH=\"$SGX_SDK/lib64\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\"; ./build/hw-release/soci_sgx_crypto_benchmark ./build/hw-release/soci_provisioning_enclave.signed.so 100 30 10 20 > results/benchmark-hw-3072.json"
    fi
    return 0
  fi
  local dc; dc="$(resolve_compose)"
  if [[ -z "$dc" ]]; then
    record_skip hw "有 SGX 设备但无本地 SGX SDK 且无 docker；无法运行 HW"
    return 0
  fi
  if (( NO_NATIVE )); then
    echo "  --no-native: 跳过原生构建"
  fi
  echo "  经 dist 镜像 (dist/compose.hw.deploy.yaml) 运行 HW"
  run_step hw check "$dc -f dist/compose.hw.deploy.yaml run --rm soci-hw check"
  run_step hw test "$dc -f dist/compose.hw.deploy.yaml run --rm soci-hw test"
  if (( RUN_BENCHMARK )); then
    # 单镜像基准: Provisioning Enclave 的 KeyGen + FULL_DECRYPT (benchmark-hw-3072.json)
    run_step hw benchmark "$dc -f dist/compose.hw.deploy.yaml run --rm soci-hw benchmark"
    # CP/CSP 双镜像协议基准: provision -> csp -> cp-benchmark
    # 产出 keygen-hw-3072.json + cp-csp-benchmark-hw-3072.json (Encrypt/SADD/ScalarMul/
    # 阈值Decrypt/SMUL/SCMP/SABS/SDIV 的 mean/P50/P95 + CP enclave 时间 + CSP 往返)
    local cp_image="${SOCI_CP_IMAGE:-soci-sgx-cp:2.26}"
    local csp_image="${SOCI_CSP_IMAGE:-soci-sgx-csp:2.26}"
    if docker image inspect "$cp_image" >/dev/null 2>&1 && docker image inspect "$csp_image" >/dev/null 2>&1; then
      echo "  运行 CP/CSP 双镜像协议性能测试 (dist/compose.hw.cp-csp.deploy.yaml)"
      # up 串起 check->test->provision->csp->cp，cp 退出即中止；始终 down 清理容器，保留 up 的退出码
      run_step hw cp-csp "$dc -f dist/compose.hw.cp-csp.deploy.yaml up --abort-on-container-exit --exit-code-from cp; _rc=\$?; $dc -f dist/compose.hw.cp-csp.deploy.yaml down; exit \$_rc"
    else
      echo "  [SKIP] hw/cp-csp: 缺少 $cp_image 或 $csp_image 镜像(单镜像基准已完成)"
    fi
  fi
}

# ---- main -------------------------------------------------------------------

echo "SOCI SGX SDK 测试报告生成器"
echo "项目目录: $PROJECT_DIR"
echo "输出目录: $OUTPUT_DIR"
echo "模式: $MODES | collect-only=$COLLECT_ONLY | benchmark=$RUN_BENCHMARK"
echo ""

if (( ! COLLECT_ONLY )); then
  probe_env
  echo "环境探测完成: $ARTIFACTS_DIR/env.txt"
  echo ""
fi

IFS=',' read -ra MODE_ARRAY <<< "$MODES"
for mode in "${MODE_ARRAY[@]}"; do
  if (( COLLECT_ONLY )); then
    echo "  [collect-only] $mode: 复用已有产物（不执行）"
    continue
  fi
  case "$mode" in
    off) run_off ;;
    sim) run_sim ;;
    hw)  run_hw  ;;
    *) echo "未知模式: $mode (应为 off|sim|hw)" >&2 ;;
  esac
  echo ""
done

echo "==> 渲染报告"
python3 "$PROJECT_DIR/scripts/render_test_report.py" \
  --project "$PROJECT_DIR" --out "$OUTPUT_DIR" --artifacts "$ARTIFACTS_DIR"

echo ""
echo "报告已生成:"
echo "  $OUTPUT_DIR/test-report.md"
echo "  $OUTPUT_DIR/test-report.json"

# 退出码: 任何已执行步骤失败 -> 非 0
if awk -F'\t' '$3 != "" && $3 != "0" { found=1 } END { exit !found }' "$ARTIFACTS_DIR/steps.tsv"; then
  echo "存在失败的步骤，以非 0 退出。" >&2
  exit 1
fi
exit 0

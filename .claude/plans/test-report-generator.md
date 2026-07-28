# SOCI SGX SDK 测试报告生成器 — 实施计划

## 目标
新增一个一键脚本，按 README 的三种构建模式（OFF/SIM/HW）**实际运行可运行的测试与基准**，
并把所有产物汇总成一份报告（Markdown + JSON）。脚本在无 SGX 环境下优雅降级，
并保留 `--collect-only` 仅汇总已有结果的开关。

## 现状结论（来自代码勘察）
- 三种模式测试入口：`ctest --preset {off-debug|off-asan|sim-release|hw-release}`；
  OFF 单测 `soci_tests`；SIM/HW 含 `soci_sgx_{cp,csp}_lifecycle / crypto_correctness / threshold_correctness`。
- 基准产物落 `results/`：`benchmark-off-3072.json`、`benchmark-sim-3072.json`、
  HW 侧 `benchmark-hw-3072.json` / `keygen-hw-3072.json` / `cp-csp-benchmark-hw-3072.json`。
- 环境信息来源：`versions.lock`（固定版本）、`build/<preset>/build-manifest.json`、
  `build/<preset>/Testing/Temporary/{LastTest.log,LastTestsFailed.log}`、
  `dist/soci-sgx-hw-2.26.image-id.txt` + `.sha256`。
- 本机能力：无 SGX SDK、无 `/dev/sgx*`、无 CPU sgx flag；OFF 可本地跑；
  SIM 可经 `docker/compose.sim.yaml`（容器内装 SDK，无需硬件）跑；
  HW 因无设备必然跳过。docker 已装，dist 三镜像已 `docker load`。
- 工具：cmake/ctest 3.28、python3 3.12、docker 29.6、docker-compose 1.29；**无 jq** → 渲染用 Python 标准库。

## 新增文件
1. `scripts/generate_test_report.sh` — 主编排脚本（bash，`set -euo pipefail`，风格对齐现有 `scripts/*.sh`）。
2. `scripts/render_test_report.py` — 报告渲染器（python3 标准库，无第三方依赖）。
3. `scripts/lib_report_common.sh`（可选）— 共用日志/探测函数；若体量小则内联进主脚本，不强行拆分。

## `generate_test_report.sh` 设计

### 用法
```bash
./scripts/generate_test_report.sh                       # 跑可运行项 + 汇总
./scripts/generate_test_report.sh --modes off           # 仅 OFF
./scripts/generate_test_report.sh --collect-only        # 不执行，仅汇总已有产物
./scripts/generate_test_report.sh --no-benchmark        # 跳过性能基准
./scripts/generate_test_report.sh --output results      # 报告输出目录（默认 results）
```
`cd "$(dirname "$0")/.."` 进项目根，与现有脚本一致。

### 流程
1. **解析参数**：`--modes <csv>`、`--collect-only`、`--no-benchmark`、`--output <dir>`、`-h/--help`。
2. **环境探测**（结果写入 `<out>/report-artifacts/env.txt`）：
   `gcc/g++`、`cmake`、`python3`、`docker`、`docker-compose`、SGX SDK 路径、
   `/dev/sgx_enclave`、`/dev/sgx_provision`、`/proc/cpuinfo` 的 sgx flag、dist 镜像 id/sha256、git rev（若有）。
3. **逐模式执行**（每个步骤捕获 stdout+stderr 与退出码到 `<out>/report-artifacts/<mode>-<step>.log`）：
   - **OFF**（本地，无需 SGX）：
     `scripts/build_off.sh` → `scripts/test_off.sh`（内部 `ctest --preset off-debug`）→
     （可选）`scripts/run_benchmark.sh 3072 50`。
     为拿到结构化用例结果，test 步骤改为 `ctest --preset off-debug -T Test`（生成 `Testing/<TAG>/Test.xml`）。
   - **SIM**：若本机有 SGX SDK → 本地 `scripts/build_sim.sh && scripts/test_sim.sh`(+`run_sim_benchmark.sh`)；
     否则若 docker 可用 → `docker-compose -f docker/compose.sim.yaml build` +
     `run --rm test`，挂载 `results` 以回收 `benchmark-sim-3072.json`（compose 已把 results 卷映射进容器）。
     均不可用 → 标记 skip 并写原因。
   - **HW**：若本机有 `/dev/sgx_enclave` 且镜像已加载 →
     `docker-compose -f dist/compose.hw.deploy.yaml run --rm soci-hw test`(+ `benchmark`)，
     以及 `dist/compose.hw.cp-csp.deploy.yaml` 的 check/test/provision/cp；否则标记 skip（原因：无 SGX 设备）。
4. **每步非致命**：单步失败仅记录失败状态，不中断后续模式；最终由渲染器据失败项下总体结论。
5. **渲染**：`python3 scripts/render_test_report.py --out <out> --artifacts <out>/report-artifacts`，
   生成 `<out>/test-report.md` 与 `<out>/test-report.json`。
6. **退出码**：任何已执行的测试步骤失败 → 退出非 0（便于 CI 串联）；全 skip 或全过 → 0。

## `render_test_report.py` 设计

### 输入（全部容错：缺失则记 N/A）
- `versions.lock`、`<out>/report-artifacts/env.txt`、各步骤 log。
- 各 `build/<preset>/Testing/<TAG>/Test.xml`（JUnit XML，`xml.etree` 解析，主数据源）；
  缺失则回退解析 `LastTest.log`（文本：`N/M Testing: <name>`、`Test Passed/Failed`、`Test time = X sec`）+
  `LastTestsFailed.log`（`<num>:<name>`）。
- `results/benchmark-*.json`、`results/keygen-*.json`、`results/cp-csp-benchmark-*.json`（`json` 标准库）。
- `build/*/build-manifest.json`、`dist/*.image-id.txt` + `.sha256`。

### 输出 1：`test-report.md`（中文，对齐 docs 风格）
1. **概要**：生成时间、生成器版本、主机、git rev、总体结论（PASS/FAIL/SKIPPED）、模式覆盖一览（OFF/SIM/HW 各 ✓/✗/skip+原因）。
2. **环境**：两列表——`versions.lock` 固定版本 vs 本机实测版本；SGX SDK/设备/CPU flag；dist 镜像 id+sha256。
3. **测试结果**（按模式分节）：汇总（passed/failed/skipped/总时延）+ 用例表（名称|状态|耗时(ms)|备注）。
4. **性能基准**（按模式分节）：operation|samples|mean|p50|p95|min|max|correct 表；HW 多表（单机/CP-CSP）。
   标注 `experimental_reference_only` 项与 SIM≠HW 说明。
5. **构建产物**：各 preset 的 build-manifest 摘要；dist 文件清单+校验和状态。
6. **说明与限制**：reference-only 协议、SIM 不代表 HW、HW 需设备等，引述 README/SECURITY/BENCHMARK。
7. **附录**：各步骤日志文件路径指针。

### 输出 2：`test-report.json`（机器可读摘要）
顶层 `{meta, environment, modes:{off/sim/hw:{status, tests:[...], benchmarks:[...], logs:[...]}}, dist, verdict}`。

## 关键设计要点
- **优雅降级**：每个模式独立探测可用性；不可用记 `status=skipped` + `reason`，不视作失败。
- **非破坏性**：报告写到 `results/`；执行产物沿用项目既有路径（`build/`、`results/`），不引入新污染目录（仅新增 `results/report-artifacts/` 存步骤日志，并加入 `.gitignore`）。
- **可复现**：环境表同时给固定版本与实测版本，便于发现漂移（如本机 GCC 13.3 vs 锁定 11.4）。
- **标准库优先**：不引入 jq/python 第三方依赖，与现有脚本零新增依赖。
- **风格对齐**：bash 用 `set -euo pipefail` + heredoc usage；中文注释/输出与 docs 一致。

## .gitignore 变更
追加 `results/report-artifacts/` 与 `results/test-report.{md,json}`（如未被现有规则覆盖）。

## 验证方式
- `./scripts/generate_test_report.sh --modes off --no-benchmark`：本机可完整跑通，生成两份报告。
- `./scripts/generate_test_report.sh --collect-only`：仅汇总，秒级返回，报告标 OFF 已有结果、SIM/HW skip。
- 人工核对 md 表格数值与 `results/*.json` 一致；核对 env 表固定版本 vs 实测。

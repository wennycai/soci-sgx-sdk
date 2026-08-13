# SOCI SGX SDK

SOCI SGX SDK 是一个面向 Linux x86_64 的阈值 Paillier SDK。项目将公开密钥
运算、协议编排和语言绑定放在非安全区，将密钥生成、密钥封存及解密放入
Intel SGX Enclave。CP 和 CSP 使用两个独立 Enclave 和服务进程。

当前版本提供：

- 稳定的 C ABI（`libsoci_sdk.so`）和 C++ RAII 封装；
- Python/pybind11 模块和 Java 8/JNI 动态库（`libsoci_jni.so`）；
- Paillier 加密、同态加法、正负标量乘和解密；
- CP/CSP 服务程序及共享的 SIM/HW EDL；
- OFF、SIM、HW 三种严格隔离的构建模式；
- CMake Presets、Docker、普通 CI 和 SGX Hardware CI；
- 版本化密文、公钥与密钥元数据，以及输入大小和模式检查。

SMUL、SCMP、SSBA、SDIV 等参考协议的安全模型不能满足生产要求，默认关闭。
具体暴露面和尚待完成的生产安全能力见 `docs/SECURITY.md`。

## 运行模式

| 模式 | 用途 | SGX 依赖 |
| --- | --- | --- |
| `OFF` | API、序列化、算法和语言绑定开发测试 | 无；密钥文件仅供测试，不保密 |
| `SIM` | 使用真实 EDL、ECALL 和 Enclave 镜像做功能测试 | Intel SGX SDK 2.26，不需要 SGX 硬件 |
| `HW` | 硬件 Enclave、正式 sealing 和发布验收 | SGX SDK 2.26、SGX CPU/BIOS 和设备 |

HW 创建失败不会降级为 SIM；SIM/OFF 密钥也不能在 HW 中加载。

## 依赖版本

推荐环境是 Ubuntu 22.04 x86_64、GCC 11.4、CMake 3.22.1、Intel SGX
SDK 2.26、Python 3.10、JDK 8、GMP 6.2 和 OpenSSL 3。完整固定版本见
`versions.lock`。

默认密码参数为 3072-bit Paillier 模数，对应约 128-bit 经典安全强度。

Ubuntu 基础依赖：

```bash
sudo apt-get update
sudo apt-get install build-essential gcc-11 g++-11 cmake \
  libgmp-dev libssl-dev python3 python3-pip openjdk-8-jdk-headless
```

SIM/HW 还需安装 Intel SGX SDK 2.26，并设置：

```bash
source /opt/intel/sgxsdk/environment
export SGX_SDK=/opt/intel/sgxsdk
./scripts/build_gmp_sgx.sh
```

`build_gmp_sgx.sh` 校验固定的 GMP 6.2.1 源码摘要并生成
`$SGX_SDK/gmp-sgx/lib/libgmp_sgx.a`。该可信静态库使用可移植的
x86_64/k8 基线汇编，不直接加载宿主 `libgmp.so`。

## OFF 模式编译和测试

```bash
./scripts/build_off.sh
./scripts/test_off.sh
./build/off-debug/soci_cpp_example
```

等价的 CMake 命令：

```bash
cmake --preset off-debug
cmake --build --preset off-debug
ctest --preset off-debug
```

内存安全测试：

```bash
cmake --preset off-asan
cmake --build --preset off-asan
ctest --preset off-asan
```

逐项性能测试：

```bash
./scripts/run_benchmark.sh 3072 50
cat results/benchmark-off-3072.json
```

它分别输出 KEYGEN、ENCRYPT、DECRYPT、SMUL、SCMP、SABS、SDIV 的
mean、P50、P95、min、max 和正确性。当前安全计算项是 OFF 模式
reference-only 基线，不是 SGX 或生产协议数据，详见 `docs/BENCHMARK.md`。

输出包括 `build/off-debug/libsoci_sdk.so`、可选的
`libsoci_jni.so`、CP/CSP 服务程序及 `build-manifest.json`。

## SIM 模式编译和测试

SIM 不需要 `/dev/sgx_enclave`，但必须安装 SGX SDK。它会使用同一份
`trusted/common/soci.edl` 生成可信/非可信桥接代码，构建 CP/CSP Enclave，
使用构建时生成的测试密钥签名，并分别执行创建、ECALL 和销毁测试。

```bash
source /opt/intel/sgxsdk/environment
./scripts/build_sim.sh
./scripts/test_sim.sh
```

或：

```bash
cmake --preset sim-debug
cmake --build --preset sim-debug
ctest --preset sim-debug
```

预期生成：

```text
build/sim-release/soci_cp_enclave.signed.so
build/sim-release/soci_csp_enclave.signed.so
build/sim-release/soci_sgx_lifecycle_test
```

没有本地 SDK 时可用 Docker：

```bash
docker-compose -f docker/compose.sim.yaml build
docker-compose -f docker/compose.sim.yaml run --rm test
```

Docker 镜像固定下载 Intel 官方的
`sgx_linux_x64_sdk_2.26.100.0.bin`。SIM 容器不映射 SGX 设备。

真实 SIM 密码学性能测试：

```bash
./scripts/run_sim_benchmark.sh 100 30 10 5
cat results/benchmark-sim-3072.json
```

它测量 Provisioning Enclave 内的 3072-bit KeyGen 和 FULL_DECRYPT，并验证
seal/unseal 后仍可正确解密。SIM 不需要 SGX 硬件；若宿主未安装 SDK，可在
上述 Docker 镜像中执行同一脚本。

## HW 模式

```bash
./scripts/check_sgx_host.sh
./scripts/build_hw.sh
./scripts/test_hw.sh
```

或使用 `docker/compose.hw.yaml`。生产签名密钥不得使用 SIM 自动生成的测试
密钥；HW 密钥必须在目标 Hardware Enclave 中重新生成。

### HW Docker 镜像部署

项目提供已经编译好 Enclave、测试程序、SGX SDK 2.26 接口和 PSW uRTS
运行库的离线镜像。目标服务器不需要安装编译器或 SGX SDK，但必须满足：

- CPU 支持 SGX，并已在 BIOS 中启用；
- 宿主 Linux SGX 驱动正常；
- 存在 `/dev/sgx_enclave` 或 `/dev/sgx/enclave`；
- 已安装 Docker 和 Docker Compose 插件。

本地构建并导出镜像：

```bash
./scripts/package_hw_image.sh
```

输出位于 `dist/`：

```text
soci-sgx-hw-2.26.tar.gz
soci-sgx-hw-2.26.tar.gz.sha256
compose.hw.deploy.yaml
```

将上述三个文件复制到目标 SGX 服务器，在文件所在目录校验并加载镜像：

```bash
sha256sum -c soci-sgx-hw-2.26.tar.gz.sha256
gzip -dc soci-sgx-hw-2.26.tar.gz | docker load
```

确认 HW 程序使用 PSW 的系统 uRTS，而不是 SDK 中的开发版 uRTS：

```bash
docker run --rm --entrypoint bash soci-sgx-hw:2.26 \
  -lc 'ldd /opt/soci/bin/soci_sgx_lifecycle_test | grep libsgx_urts'
```

输出应指向 `/lib/x86_64-linux-gnu/libsgx_urts.so.2` 或
`/usr/lib/x86_64-linux-gnu/libsgx_urts.so.2`，不能指向
`/opt/intel/sgxsdk/lib64`。

检查 SGX 设备映射：

```bash
docker-compose -f compose.hw.deploy.yaml run --rm soci-hw check
```

运行 HW 生命周期与密码正确性测试：

```bash
docker-compose -f compose.hw.deploy.yaml run --rm soci-hw test
```

运行 HW KeyGen 和解密性能测试：

```bash
docker-compose -f compose.hw.deploy.yaml run --rm soci-hw benchmark
cat results/benchmark-hw-3072.json
```

运行同一台 SGX 服务器上的 CP/CSP 双镜像测试：

```bash
docker-compose -f compose.hw.cp-csp.deploy.yaml run --rm check
docker-compose -f compose.hw.cp-csp.deploy.yaml run --rm test

docker-compose -f compose.hw.cp-csp.deploy.yaml up \
  --abort-on-container-exit --exit-code-from cp
cat results/keygen-hw-3072.json
cat results/cp-csp-benchmark-hw-3072.json
docker-compose -f compose.hw.cp-csp.deploy.yaml down
```

完整流程也会自动执行检查和测试，顺序为
`check → test → provision → CSP/CP`。`check` 验证 CPU SGX 标志和
`/dev/sgx_enclave` 映射；`test` 实际创建 CP、CSP、Provisioning Enclave，
执行生命周期、阈值 KeyGen、CP/CSP partial decrypt 和 CSP combine decrypt
正确性测试；随后
Provisioning Enclave 生成 3072-bit 阈值密钥并输出公钥、
`cp.sealed` 和 `csp.sealed`；随后 CP、CSP 镜像只加载各自的密封份额。
宿主和共享卷中不会出现明文私钥份额。CP 通过 Compose 内部 TCP 网络访问
CSP；两者可以映射同一个宿主 `/dev/sgx_enclave`。默认每项协议预热 20 次、
统计 100 次，可通过 `PROTOCOL_WARMUP` 和 `PROTOCOL_SAMPLES` 覆盖。

结果逐项包含 Encrypt、SADD、ScalarMul、阈值 Decrypt、SMUL、SCMP、
SABS、SDIV 的 mean/P50/P95、CP Enclave 时间、CSP 往返时间和正确性。
SIM/HW 的 SMUL、SCMP、SABS、SDIV 使用 SOCI-plus 半诚实协议结构和 CP/CSP
阈值解密：SMUL 双输入掩码并按 `X^L · Y` 打包，SCMP 随机化并随机翻转差值，SABS 组合 SCMP 与
SMUL，SDIV 逐位组合 SCMP 与 SMUL。CSP 不再获得 SCMP/SDIV 的原始操作数。
OFF 中同名算子仍是 `experimental_reference_only` 的解密—计算—重加密基线。

默认参数为 KeyGen 预热 20 次、统计 30 次，解密预热 10 次、统计 100 次。
可以在运行前覆盖：

```bash
KEYGEN_WARMUP=30 KEYGEN_SAMPLES=50 \
DECRYPT_WARMUP=20 DECRYPT_SAMPLES=200 \
docker-compose -f compose.hw.deploy.yaml run --rm soci-hw benchmark
```

如果宿主设备名是 `/dev/sgx/enclave`：

```bash
SGX_ENCLAVE_DEVICE=/dev/sgx/enclave \
docker-compose -f compose.hw.deploy.yaml run --rm soci-hw test
```

当前 HW 测试不包含远程证明，因此不需要 PCCS、QCNL、AESM socket、
`/dev/sgx_provision` 或 DCAP Quote 组件。Compose 只外挂 SGX Enclave
设备、`runtime/hw` 数据目录和 `results` 结果目录。

### 拷贝到 SGX 主机后一键运行（不使用 Docker）

目标机器需要预先安装 Intel SGX SDK 2.26、编译工具和 SGX 驱动。将整个项目
目录拷贝过去后，在项目根目录执行：

```bash
./scripts/run_native_sgx.sh
```

脚本检测到 `/dev/sgx_enclave`、`/dev/sgx_provision` 和 CPU SGX 标志时自动
选择 HW，否则选择 SIM。也可以明确指定模式：

```bash
./scripts/run_native_sgx.sh hw
./scripts/run_native_sgx.sh sim
```

同时运行 KeyGen 和解密性能测试：

```bash
./scripts/run_native_sgx.sh hw --benchmark
cat results/benchmark-hw-3072.json
```

脚本会依次检查环境、在项目 `.deps` 中构建可信 GMP、编译 Enclave、运行
正确性测试，并按需运行性能测试，不会向 SGX SDK 安装目录写入文件。如果
SDK 不在 `/opt/intel/sgxsdk`，可这样指定：

```bash
SGX_SDK=/实际的/sgxsdk/路径 ./scripts/run_native_sgx.sh hw --benchmark
```

## 测试报告生成

`scripts/generate_test_report.sh` 一键执行可运行的测试与基准，并汇总为
Markdown + JSON 报告。按本机能力自动降级：无 SGX 设备则跳过 HW，无 dist
镜像则 SIM 回退到 `compose.sim.yaml`。完整参数见 `--help`。

```bash
./scripts/generate_test_report.sh                   # 默认 off,sim,hw
./scripts/generate_test_report.sh --modes off       # 只跑 OFF（最快）
./scripts/generate_test_report.sh --collect-only    # 不执行，仅汇总已有产物
./scripts/generate_test_report.sh --no-benchmark    # 跳过性能基准
./scripts/generate_test_report.sh --no-native       # 强制走镜像，不用本机 SGX SDK 原生构建
./scripts/generate_test_report.sh --output results  # 报告输出目录（默认 results）
```

- 任何已执行步骤失败 -> 脚本非 0 退出；全跳过或全过 -> 0。
- 报告产物：`<output>/test-report.md`、`<output>/test-report.json`，详细日志与
  各步产物在 `<output>/report-artifacts/`。
- HW 模式（需 SGX 设备）除单镜像基准（KeyGen + FULL_DECRYPT）外，还自动跑
  CP/CSP 双镜像协议基准（Encrypt/SADD/ScalarMul/SMUL/SCMP/SABS/SDIV 等，
  需 `soci-sgx-cp`/`soci-sgx-csp` 镜像）；`--no-benchmark` 跳过全部基准。

在 SGX 服务器上，加载 dist 镜像后直接：

```bash
gzip -dc dist/soci-sgx-hw-2.26.tar.gz | docker load   # 含 hw/cp/csp 三个镜像
./scripts/generate_test_report.sh --modes hw --no-native
```

> 若服务器上**也装了本机 Intel SGX SDK**，脚本默认会优先原生编译（需要源码）。
> 镜像部署、无源码时务必加 `--no-native`（或 `SOCI_NO_NATIVE=1`），强制走 dist 镜像，
> 不碰宿主源码。该路径只需 `scripts/` + `dist/*.yaml` + 镜像，不需要项目源码。

## C++ 示例

```cpp
#include <soci/soci.hpp>
soci::Runtime runtime("runtime/off");
runtime.create_key("demo"); // 默认 3072-bit，约 128-bit 安全强度
auto a = runtime.encrypt("20");
auto b = runtime.encrypt("22");
auto result = runtime.add(a, b);
std::string plaintext = runtime.decrypt(result); // "42"
```

## Python SDK

安装 pybind11 后重新配置，CMake 会生成 `_soci`：

```bash
python3 -m pip install pybind11==2.13.6 scikit-build-core==0.10.7
python3 -m pip wheel ./bindings/python
```

Python 明文通过十进制字符串转换，支持任意精度整数；密文可与 `bytes`
互转。

接口正确性与绑定层性能测试：

```bash
SOCI_SGX_MODE=OFF SOCI_ENABLE_EXPERIMENTAL_PROTOCOLS=1 \
LD_LIBRARY_PATH=build/off-python \
python3 tests/python_binding_benchmark.py build/off-python
```

## Java SDK

设置 `JAVA_HOME` 后构建：

```bash
export JAVA_HOME=/path/to/jdk8
cmake --preset off-debug
cmake --build --preset off-debug
cd bindings/java && mvn package
```

运行前将 `build/off-debug` 加入 `java.library.path`。JNI 通过
`System.loadLibrary("soci_jni")` 加载。

Java/JNI 接口测试覆盖 Encrypt、Decrypt、SADD、ScalarMul、SMUL、SCMP、
SABS 和 SDIV。测试类位于
`bindings/java/src/test/java/com/soci/sdk/BindingBenchmark.java`。
Python/Java 的上述测试使用 OFF reference-only 后端来单独测量语言绑定；
它们不能替代 `cp-csp-benchmark-hw-3072.json` 中的真实 HW Enclave 数据。

## 目录

- `include/soci`：C/C++ 公共接口；
- `src`：非安全区核心实现；
- `trusted`：共享 EDL、CP/CSP Enclave；
- `bindings`：Python 和 Java 绑定；
- `services`：CP/CSP 服务；
- `tests`：OFF 与 SGX 生命周期测试；
- `scripts`、`docker`、`.github/workflows`：构建、复现和 CI。

密钥目录应按 `runtime/off`、`runtime/sim/{cp,csp}` 和
`runtime/hw/{cp,csp}` 隔离。部署和安全限制分别见
`docs/DEPLOYMENT.md` 与 `docs/SECURITY.md`。

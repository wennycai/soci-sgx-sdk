# 性能测试

运行：

```bash
./scripts/run_benchmark.sh 3072 50
```

输出 `results/benchmark-off-3072.json`。3072-bit Paillier/RSA 类模数作为
约 128-bit 经典安全强度配置；2048-bit 仅约 112-bit，不再作为默认值。
每项记录样本数、平均值、P50、
P95、最小/最大毫秒数和结果正确性。

当前 OFF benchmark 是 SOCI-plus 协议功能模拟：SMUL 解密双掩码操作数，
SCMP 只解密随机换向和缩放后的差值，SSBA/SABS 组合 SCMP 与 SMUL，SDIV
逐位组合 SCMP 与 SMUL。OFF 单进程持有完整测试密钥，因此只用于 API、协议
代数正确性和性能回归，不代表双方隔离部署的安全性或 SGX 性能。

SIM/HW 的 CP/CSP benchmark 使用 SOCI-plus 协议编排：SMUL 对两个输入分别
添加 128-bit 随机掩码，再以 `C = X^L · Y` 打包后执行一次阈值解密；SCMP
向 CSP 发送随机方向、随机比例隐藏后的差值；
SABS 组合 SCMP 与 SMUL；SDIV 逐位组合 SCMP 与 SMUL并返回密文商和余数。
安全标签为 `soci-plus-masked-threshold` 或 `soci-plus-composed`。这些标签
表示半诚实协议结构，不表示已经具备恶意安全、重放保护或侧信道加固。

SIM 密码学测试：

```bash
./scripts/run_sim_benchmark.sh 100 30 10 5
```

输出 `results/benchmark-sim-3072.json`。该测试使用 Provisioning Enclave
内的 SGX 随机数和可信静态 GMP 6.2.1 完成真实 3072-bit Paillier KeyGen，
导出公钥后
在非安全区加密，再通过 `ecall_decrypt` 完整解密。测试还会关闭密钥状态、
从 SGX sealed blob 恢复并再次验证解密。

参数依次是解密正式样本数、密钥生成正式样本数、解密 warm-up 次数和
密钥生成 warm-up 次数。KeyGen 默认先执行 5 次 warm-up、统计 30 次；
Decrypt 默认先执行 10 次 warm-up、统计 100 次。所有
warm-up 均不进入统计。计时采用宿主 `steady_clock`，包含 ECALL 边界切换和
Enclave 内运算，因此属于端到端调用延迟。

KeyGen 的随机素数搜索具有固有长尾；增加 warm-up 只用于排除首次代码页、
堆分配和运行时初始化影响，不会也不应该消除这部分密码学随机波动。

可信 GMP 使用固定 x86_64/k8 基线汇编，不启用 fat-binary CPUID 动态分派。
`ENCLAVE_KEYGEN_SEAL_EXPORT` 的计时包含素数生成、Paillier 参数计算、公钥
导出、私钥序列化和 SGX sealing；`ENCLAVE_FULL_DECRYPT` 包含 ECALL 输入/
输出复制、模幂和明文序列化。两者均不包含 Enclave 创建时间。

SIM 数据只代表模拟模式的功能和相对性能，不代表 Hardware Enclave 性能。
CP/CSP 部分解密与经过认证的份额 provisioning 尚未完成，因此结果只列
`ENCLAVE_KEYGEN` 和 `ENCLAVE_FULL_DECRYPT`，不会将完整解密冒充部分解密。

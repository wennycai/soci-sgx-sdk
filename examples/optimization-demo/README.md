# Phase 1–5 密态最优化交互演示

现有 Demo 已接入真实 confidential optimization 链路：

```text
Java/HTTP → Demo JNI bridge → ThresholdConfidentialRuntime
          → ThresholdSecureOps → ConfidentialOptimizer
          → PredicateEngine → Phase 5 Encrypted Branch-and-Bound
```

Demo 保留双通道一致性页面和 `.xlsx/.enc` 三方工作流。浏览器 plaintext
reference 只验证最终 total、C12 和 solution 一致性；页面展示的节点、谓词和耗时
全部来自 `EncryptedOptimizationStats`。

## 一条命令启动

优先使用 SIM：

```bash
./examples/optimization-demo/run_demo.sh sim 8080
```

开发环境没有 Intel SGX SDK 时使用 OFF fallback：

```bash
./examples/optimization-demo/run_demo.sh off 8080
```

访问 <http://127.0.0.1:8080>。脚本会构建 native/JNI、编译 Java 服务并启动
页面；SIM 脚本还会 provision threshold keys 并启动独立 CSP 服务。

通过 `docker/compose.sim.yaml` 启动时，容器会设置
`SOCI_DEMO_BIND=0.0.0.0`，使 Docker 的端口映射可从宿主机访问。本机直接启动时
默认仍只监听 `127.0.0.1`。

## 页面与操作

- 双通道模式：输入成本和阈值，选择 `current_suffix` 或 `lagrangian`，每次只执行
  一种 confidential strategy，并与独立 plaintext oracle 核对。
- 三方角色模式：
  - A（数据使用方）提交公开阈值和策略需求；
  - C（数据拥有方）上传 `.xlsx`，加密并导出 `.enc`；
  - B（密态计算服务方）导入密文并执行优化，再将结果 `.enc` 返回；
  - C 执行最终授权，结果交付 A。

页面展示真实 Paillier 密文片段，以及 `visited_nodes`、`pruned_nodes`、
`candidate_count`、`prune_predicates`、`accept_predicates` 和
preprocessing/search/total time。不会展示成本中间值、LB、`linear_upper`、lambda
winner 或 prune reason。

## SIM、OFF 与当前安全边界

- SIM 走真实 CP/CSP、`ThresholdSecureOps` 和 threshold Predicate resolver，但
  Intel SGX Simulation 不提供硬件隔离，不能当作 HW 安全或性能证明。
- OFF 使用相同 `ConfidentialOptimizer`、PredicateEngine 和 Phase 5 solver 语义，
  但密钥和运算都在普通进程中，只适合开发。
- Demo bridge 是最小展示接口，不是完整 Phase 7 Java SDK。它采用本机单进程 HTTP
  服务和内存 job/result token 模拟 A/B/C 交接；尚未提供生产身份认证、远程证明、
  持久化多租户密钥生命周期、TLS、审计存储或结果授权签名。
- JNI 不暴露 generic decrypt-bit/reveal API；solver 仍只通过 PredicateEngine
  reveal 最终 PRUNE/ACCEPT。Demo 最终汇总展示由 C 的原输入和授权 solution 重建，
  不解密中间 bound。

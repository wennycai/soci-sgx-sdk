# 密态最优化交互演示

这是一个 Java/JNI 驱动的 OFF 模式演示。浏览器通过本地 HTTP API 调用 Java
封装，Java 再通过 `libsoci_jni.so` 调用 SOCI SDK；密文不再由前端伪造。

```bash
./examples/optimization-demo/run_off_demo.sh 8080
```

浏览器访问 `http://127.0.0.1:8080`。启动脚本构建 OFF SDK 与 JNI、编译零第三方
依赖的 Java HTTP 服务，然后由该服务同时提供静态页面和 `/api/*` 接口。

明文耗时由浏览器参考求解器重复测量；SDK 路径显示 HTTP、Java、JNI 和 OFF
SDK 的端到端实测时间。当前 SDK 优化控制层仍保留定点成本系数进行分支定界，
不能解读为求解器控制流已经全程只接触密文。

## 用户交互工作台

访问 `workflow.html` 可进入 A/B 双角色模式：A 是持有私钥的数据拥有方，可将
明文 Excel 加密后交给 B，或导入 B 返回的计算结果密文并只解密结果列；B 是
不持有私钥的数据使用方，只能导入 A 的密文、选择最优化算子并将密文结果返还
给 A。A 解密最后一列后导出 JSON 结果给 B。示例
`sample-costs.xlsx` 是实际 OOXML 工作簿；`.enc` 是 ZIP-compatible 容器：

- `encrypted-data.xlsx`：SDK 生成的 Paillier 成本密文；
- `manifest.json`：格式版本、算法、Key ID 与密文结果。

工作流中的成本矩阵、优化结果及解密均调用 Java/JNI SDK。`.enc` 包保存 SDK
生成的 Paillier 密文；OFF 私钥只保存在本地运行目录中。OFF 不提供 SGX 隔离，
demo 后端使用不透明作业 ID 在会话内关联 A 的模型，B 的浏览器不接触明文或
私钥。生产部署仍应切换到 SIM/HW 的 CP/CSP 服务与正式密钥生命周期。

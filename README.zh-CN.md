# hive-immune（群体智能防线）

[English](README.md)

**面向企业网络的群体智能防御系统。** 不依赖一个中心大脑和一道城墙：每个节点运行一个轻量 Agent，在本地感知异常，给邻居留下**带签名、会衰减的"威胁信息素"**，然后通过**信誉加权的群体共识**决定是否行动。

> 当前状态：**0.2.0。** 真实的 Falco、Tetragon eBPF 事件会作为签名信号，经 gossip 传到每个节点，由各节点计算群体决策；新增的 `hive-gateway` 会内联拦截 Agent 发出的每个 MCP 工具调用（策略 × 污点 × 审批通道 × capability 令牌 × 群体级别，全程留审计日志）。网络层决策目前仍是建议，工具边界是强制的；gossip 走普通 HTTP，载荷带签名。部署前请先看"已知局限"。

## 端到端演示（Docker，内核需开启 BTF）

三个群体节点加一个真实的 Falco 传感器：

```sh
docker compose -f deploy/compose/docker-compose.yml up -d --build
docker run --rm alpine cat /etc/shadow           # 在 node-1 上触发 Falco 规则
curl -s localhost:7956/v1/status                 # node-2 的视角：node-1 被围堵，同 zone 进入观察
docker compose -f deploy/compose/docker-compose.yml logs node-3   # 以 JSON 行输出的决策
docker compose -f deploy/compose/docker-compose.yml down -v
```

完整步骤和生产部署见 [docs/quickstart.md](docs/quickstart.md)。

## 快速体验

需要 Go 1.22 或更高版本。

```sh
go run ./cmd/hive-sim                     # 参考场景，每 10 个 tick 打印一次网络图
go run ./cmd/hive-sim -every 0 -seed 7    # 只看汇总结果，换一个随机种子
go run ./cmd/hive-sim -h                  # 查看全部参数
```

同样的参数，每次运行结果都完全一样，方便复现和对比。

### 网关（给 MCP 服务加闸）

```sh
go build -o hive-gateway ./cmd/hive-gateway
hive-gateway keygen -out root.key
hive-gateway issue -agent agent-1 -key root.key -tool search_emails -out agent-1.tok
hive-gateway serve -agent agent-1 -policy tools.yaml -audit audit.jsonl -- ./my-mcp-server
```

被拒绝的调用会以普通工具错误的形式回到模型，上游服务器根本不会被调用。完整参数、策略文件格式和审批 webhook 见 [docs/gateway.md](docs/gateway.md)；AgentDojo 评测结果见 [docs/eval.md](docs/eval.md)。

### 接入真实传感器

```sh
hive-agent keygen -out node.key
falco -o json_output=true | hive-agent run -node web-1 -key node.key -source falco
```

Tetragon 接入、安全参数和部署注意事项见 [docs/sensors.md](docs/sensors.md)。

## 模块

| 包 | 层 | 作用 |
|---|---|---|
| `pkg/pheromone` | 信息素场 | 随时间衰减、按距离加权的信号场；单个来源的贡献有上限，防止刷屏；拒绝未来时间戳 |
| `pkg/envelope` | 完整性 | Ed25519 签名，编码无歧义并带域分隔；伪造或篡改的信号进不了信息素场 |
| `pkg/quorum` | 决策 | 信誉加权的群体感应，分级响应（观察 → 围堵 → 隔离），有最少投票人数要求 |
| `pkg/sim` | 仿真 | 网格网络、扩散的入侵者、误报噪声，以及会诬陷邻居、伪造信号的恶意节点 |
| `pkg/sensor` | 感知 | 解析 Falco、Tetragon 的 JSON 事件（按不可信输入处理：限长、校验、模糊测试），生成关于本节点的信号；支持主机绑定、时间窗口和冷却 |
| `pkg/keyfile` | 身份 | 节点密钥的生成与存储（权限 0600，不会覆盖已有文件） |
| `pkg/cluster` | 成员 | `peers.json`：成员、公钥、gossip 地址、zone |
| `pkg/swarm` | 决策 | 把信息素场换算成每个节点的级别：自报告、对端投票、zone 联动 |
| `pkg/node` | 运行时 | HTTP gossip、防重放、状态接口、Falco `http_output` 接入 |
| `pkg/gateway` | 拦截 | 内联 MCP `tools/call` 网关：降级模式 → capability → 限速/预算 → 群体级别 → 风险 × 污点，带 JSONL 审计和审批 webhook |
| `pkg/capability` | 最小权限 | 基于 biscuit 的会话令牌，绑定 Agent、工具与有效期 |
| `pkg/dsse`、`pkg/credential` | 分发 | 防篡改的签名凭证文件（`hive-agent verify`） |
| `cmd/hive-sim` | 命令行 | 运行仿真并渲染网络图 |
| `cmd/hive-agent` | 命令行 | `serve` 运行节点，`run` 接传感器管道，`init-cluster`、`keygen` |
| `cmd/hive-gateway` | 命令行 | `serve` 运行网关，`keygen`/`issue` 签发 capability 令牌 |
| `eval/` | 证据 | 带网关的 AgentDojo 评测（[docs/eval.md](docs/eval.md)） |

## 已验证的安全性质

- **拜占庭上界**：默认策略下，恶意投票权重低于 1/3 时，无法让健康节点被围堵（在 5000 个随机群体上做了属性测试）
- **不可伪造**：只有能用所声称来源的公钥验证通过的信号才会被接受（单元测试加模糊测试）
- **抗刷屏**：单个来源对任一节点的贡献不超过 `OriginCap`
- **抗时钟攻击**：时间戳超前超过 `MaxSkew` 的信号直接拒绝
- **工具调用拦截（已实测）**：在 AgentDojo workspace 套件上，网关精确拒绝其策略针对的调用（deny 模式下每一次效用损失都能对应到一条审计拒绝记录），全量批准通道下零额外开销（32.5% = 与无网关完全持平）；注入成功 0/24——但无网关基线同样是 0/57（当前模型档位不会执行注入），ASR 下降的结论要等能执行注入的模型档位（[docs/eval.md](docs/eval.md)）

## 已知局限

- **传输**：gossip 走普通 HTTP。载荷有签名，也做了防重放，但没有加密；任何能访问节点的主机都能向它发送（仍需签名的）数据，也能读取 `/v1/status`。在 mTLS 实现之前，请部署在可信网段内
- **规模**：gossip 是全连接转发，适合几十个节点以内
- **网络层决策只给建议**：以 JSON 日志和 webhook 形式输出；工具边界是强制的（hive-gateway 内联拒绝），但还没有 Cilium/安全组这类执行适配器
- **网关**：只支持 stdio 传输，一个进程一个上游 MCP 服务器，stdio 链路没有加密；`-admin` 控制面可以重置污点状态——请绑定 localhost，参考 `deploy/k8s/network-policy.yaml`
- 传感器信号目前只描述本节点；只有自报告时，对端投票这条路径不会被触发
- 仿真里的信誉更新用的是真实答案（ground truth）；实际部署需要事后确认机制（分析师判定、金丝雀攻击）
- 恶意节点比例接近 1/3，或入侵扩散快于检测时，效果会下降；请按你的网络拓扑调整 `-field-scale` 和 `-vote-radius`，并关注误隔离数量
- 评测的安全结论在当前模型档位下尚无分辨力（无网关基线注入成功 0/57）；引用 ASR 数字前请换用会执行注入的模型档位重跑

## 参与贡献与安全报告

见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全漏洞请按 [SECURITY.md](SECURITY.md) 私下报告，不要发公开 issue。

## 许可证

[Apache License 2.0](LICENSE)

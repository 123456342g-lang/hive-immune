# hive-immune（群体智能防线）

[English](README.md)

**面向企业网络的群体智能防御系统。** 不依赖一个中心大脑和一道城墙：每个节点运行一个轻量 Agent，在本地感知异常，给邻居留下**带签名、会衰减的"威胁信息素"**，然后通过**信誉加权的群体共识**决定是否行动。

> 当前状态：**0.1.0 预览版。** 真实的 Falco、Tetragon eBPF 事件会作为签名信号，经 gossip 传到每个节点，由各节点计算群体决策。决策目前只是建议（JSON 日志加 webhook），不会自动执行；gossip 走普通 HTTP，只有载荷带签名。部署前请先看"已知局限"。

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
| `cmd/hive-sim` | 命令行 | 运行仿真并渲染网络图 |
| `cmd/hive-agent` | 命令行 | `serve` 运行节点，`run` 接传感器管道，`init-cluster`、`keygen` |

## 已验证的安全性质

- **拜占庭上界**：默认策略下，恶意投票权重低于 1/3 时，无法让健康节点被围堵（在 5000 个随机群体上做了属性测试）
- **不可伪造**：只有能用所声称来源的公钥验证通过的信号才会被接受（单元测试加模糊测试）
- **抗刷屏**：单个来源对任一节点的贡献不超过 `OriginCap`
- **抗时钟攻击**：时间戳超前超过 `MaxSkew` 的信号直接拒绝

## 已知局限

- **传输**：gossip 走普通 HTTP。载荷有签名，也做了防重放，但没有加密；任何能访问节点的主机都能向它发送（仍需签名的）数据，也能读取 `/v1/status`。在 mTLS 实现之前，请部署在可信网段内
- **规模**：gossip 是全连接转发，适合几十个节点以内
- **只给建议**：决策以 JSON 日志和 webhook 形式输出，还不会自动执行
- 传感器信号目前只描述本节点；只有自报告时，对端投票这条路径不会被触发
- 仿真里的信誉更新用的是真实答案（ground truth）；实际部署需要事后确认机制（分析师判定、金丝雀攻击）
- 恶意节点比例接近 1/3，或入侵扩散快于检测时，效果会下降；请按你的网络拓扑调整 `-field-scale` 和 `-vote-radius`，并关注误隔离数量

## 参与贡献与安全报告

见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全漏洞请按 [SECURITY.md](SECURITY.md) 私下报告，不要发公开 issue。

## 许可证

[Apache License 2.0](LICENSE)

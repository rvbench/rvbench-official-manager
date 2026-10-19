<p align="center">
  <img src="assets/rvbench-logo.svg" alt="rvbench" width="720">
</p>

# rvbench-official-manager

RISC-V 算子评测的控制面服务。统一接收 `JobRequest`，维护队列与 worker 注册，做准入匹配、原子授予、租约与结果账本，并提供观测汇总与四标签页控制台。

独立可运行：只依赖 [`rvbench-protocol`](https://github.com/rvbench/rvbench-core-rust)，与 worker 之间没有共享代码。worker 在 `manager: null` 时也能单独工作，接上本服务后由本服务分配任务。

## 职责边界

| 做 | 不做 |
|---|---|
| 接收、校验、持久化作业请求 | 编译候选、执行算子、计时 |
| 按 backend / implementation / kind / op / dtype / readiness 准入 | 产生数值结论或性能样本 |
| Push / Pull / Hybrid 三通道统一授予与 lease | 认证与节点名单（v1 无认证） |
| 结果账本、事件去重、观测汇总 | 修改 worker 侧证据 |

`done` 是服务终态，不等于科学评测通过。

## 一致性要点

- SQLite WAL + `synchronous=FULL`，单快照事务保存控制状态；事务内不含网络与子进程。
- 先提交分配事务再派发；丢失响应重发同一 assignment，worker 侧 attempt 索引去重。
- 心跳 TTL 30s，执行 lease 30s；授予超时标 `uncertain`，保留原归属，绝不自动跨板重跑。
- `request_id` / `client_request_id` 持久化，重复请求返回同一回执，摘要不同返回 409。
- 重启读取原 epoch 与授予，不重派在途执行；drain 持久化，只停新分配。

## 目录

```text
src/lib.rs              HTTP 服务、队列、准入、授予、账本
src/observability.rs    /metrics、观测汇总、HTTP SD、range、results、leaderboard
webui/                  静态页面：K3 监控面板 dashboard.html 与历史设计稿
contract/openapi.yaml   本服务 HTTP 接口（引用主仓共享 schema）
contract/state-machine.md  作业生命周期约定
tests/                  contract 与 observability 的 conformance 测试
config.example.json     最小配置
```

## 构建与运行

```sh
cargo build --release --locked
./target/release/rvbench-manager --config config.json
```

`config.example.json` 是最小配置，拒绝未知字段：

```json
{ "listen": "0.0.0.0:18800", "data_dir": "/home/c4y/.local/share/rvbench/manager", "victoriametrics": null }
```

`data_dir` 下会创建 `manager.sqlite` 与排他锁 `manager.lock`；同一目录只允许一个实例。真实 `config.json` 不入库。

板端交叉编译：

```sh
cargo zigbuild --release --target riscv64gc-unknown-linux-gnu.2.38
```

## 测试

```sh
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

覆盖：push/pull 竞争只授予一次、过期执行不重复分配、lease 归属校验、事件重放去重、重启后幂等、无 VictoriaMetrics 时作业不受阻、非法观测查询返回 4xx。

## 协议的来源

`rvbench-protocol` 以 git 依赖固定在 `Cargo.toml` 的 `rev`。升级协议时改 `rev` 并重新 `cargo update -p rvbench-protocol`，不要在本地改依赖源码。

wire 正本在主仓 [`rvbench/contracts/openapi.json`](https://github.com/rvbench/rvbench/blob/main/contracts/openapi.json)；本仓 `contract/openapi.yaml` 用 raw URL 以 `$ref` 引用它，不自带副本。接口变更顺序：改正本 → 同步协议仓 → 重新生成类型 → conformance 测试 → 实现。

## 相关仓库

| 仓库 | 内容 |
|---|---|
| `rvbench` | CLI、运维工具、schema 与 wire 正本、示例评测集 |
| [`rvbench-core-rust`](https://github.com/rvbench/rvbench-core-rust) | `rvbench-protocol`：生成类型、校验、canonical JSON、事务存储、内嵌控制台 |
| `rvbench-spacemit-worker` | 板端执行服务 |
| `rvbench-official-suites` | 完整官方评测集 |

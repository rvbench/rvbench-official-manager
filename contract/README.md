# rvbench-manager contract v1.0.0

状态：2026-10-17 用户已批准实施。本目录先于产品 Cargo.toml 和 src 建立。

- HTTP 权威 `openapi.yaml`；共享 wire 引用主仓正本 `contracts/openapi.json`（`$ref` 走 raw URL 指向 `rvbench/rvbench` 的 `main`，跨仓不复刻副本）。
- 状态机 `state-machine.md`；跨端约束见协议仓 `invariants.md`。
- compiler / evaluator 边界见 worker 仓 `contract/backend.md`。
- 正反例和 codegen 见协议仓，实现与部署说明见主仓 `docs/manager-worker.md`。

无认证、无 token 配置、无节点名单；任意 worker 可按 schema 注册。
保留 job / attempt / lease / epoch 与幂等约束，它们承担一致性检查。
worker 独立工作；Push / Pull 共用授予和执行路径；func 仅编译验证。
必须使用生成 wire 类型；接口变更先改 contract，再生成、测试和实现。

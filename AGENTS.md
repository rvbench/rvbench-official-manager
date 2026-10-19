# Contract-first development

用户要求新目录先创建 contract，并在整体方案审批后再实现。
先阅读本目录 contract/README.md；共享 wire 合同在 rvbench-core-rust 仓。

必须遵循：契约与正反例 -> 评审冻结 -> 生成 wire 类型 -> conformance 测试 -> 实现。
2026-10-17 用户已明确批准实施。当前 v1 基线已建立并生成；接口变更仍必须先改 contract。
接口变化先改人工权威 OpenAPI / shared schema，再生成；不得反向从 handler 固化协议。
生成类型不可手改，不得新增平行 wire DTO。内部领域类型应显式转换。

manager 只负责管理与协调，不接管 worker 的本地评估功能。
继续使用 Axum / Tokio、correctness / performance、Push / Pull，网页为自包含 HTML。
当前 manager / worker 接口无认证，不保留认证配置项；允许任意 worker 注册。
保留请求校验、任务归属、执行 lease、epoch 与幂等约束，不将这些标识当作认证凭据。
不要将 libacg 的业务依赖或未冻结骨架当作 rvbench 依赖。

本仓自 2026-10-19 起从 rvbench 主仓独立，只依赖 rvbench-protocol。

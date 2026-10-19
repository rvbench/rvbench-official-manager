# rvbench Web UI

评测服务器前端页面设计与实现的统一目录。

> 2026-10-19 自主仓整体迁入 `rvbench-official-manager`。四标签页控制台仍由协议 crate 的 `CONSOLE_HTML` 提供，本目录只放静态页面与设计稿。

- 四标签页控制台已移入 `rvbench-protocol`（`CONSOLE_HTML`），两端直接内嵌。
  包含系统状态、任务提交、任务结果、排行榜，支持明暗主题，所有内容内联。
  K1/K3 与 native C/Triton 可独立选择，按各实现探测能力展示算子、dtype 和匹配节点。
  接口与部署见 [observability.md](https://github.com/rvbench/rvbench/blob/main/docs/observability.md)。

- `dashboard.html`：现有 K3 监控页面，单文件、零构建依赖。
- `design/k3-evald-specs.html`：原服务规格设计稿，作为历史设计参考。

页面可直接在浏览器打开。Prometheus 地址通过 `?prom=<url>` 覆盖，沿用既有 CORS 和 localStorage 配置。平台 API 与队列属于 Rust runtime/backends。

后续评测集选择、提交、状态、结果与证据页面，以及共用资源和构建配置，统一归入本目录；当前 dashboard 的功能是监控。

`rvbench-tools bundle` 从协议 crate 生成控制台与 OpenAPI，从 worker 仓取适配器、从 manager 仓取配置与接口定义，与主仓的监控配置、部署脚本一起打包。
当前 VictoriaMetrics 配置位于主仓 `deploy/observability/`；旧 Prometheus 配置位于主仓 `backends/spacemit/k3/monitor/`。

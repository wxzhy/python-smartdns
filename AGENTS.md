# AGENTS.md

生成代码时请遵循以下规则：

- 代码应尽量简洁、清晰、易维护，避免过度设计。
- 优先使用标准库、成熟库和官方推荐 API 完成功能，尽量不要重复造轮子。
- 能直接调用库函数时，不要手写冗长实现。
- 保持函数职责单一，减少不必要的抽象、包装和样板代码。
- 命名应清晰直接，便于理解和维护。
- 注释应适量，只解释关键意图、边界条件和非显然设计，不要逐行翻译代码。
- 修改代码时尽量保持与现有项目风格一致，避免无关重构。
- 当第三方库、框架、配置项或 API 用法存在不确定性时，必须先查文档再实现。
- 优先使用 Context7 查阅官方或权威文档，不要凭猜测写代码。
- 如果存在合理但未确认的假设，需明确写出假设，不要静默臆断。

项目约定：

- 主包固定为 `dns_forwarder`，核心目录为 `config`、`core`、`server`、`resolver`、`pipeline`、`dispatcher`、`plugin_api`、`webui`。
- 配置文件固定为单一 `config.yaml`；配置校验统一走 `pydantic` / `pydantic-settings`。
- DNS 处理核心统一使用 `dnspython`；不要手写协议编解码替代 `dnspython` 已有能力。
- WebUI 基于 `FastAPI + Jinja`，首版支持配置保存与手动 reload，不引入额外前端构建链。
- 插件从本地 `plugins/` 目录加载；插件模块必须导出 `plugin` 实例，并遵守 `Plugin` 协议。
- 插件相关变更必须同时考虑 `context_registry`、`resolver_registry`、`answer_registry` 三类注册表边界。
- 测试统一使用 `pytest`，异步测试使用 `pytest-asyncio`；不要新增 `unittest` 风格测试。
- 任何涉及第三方库新增用法、协议细节或框架特性的实现，如果不能 100% 确认，先查 Context7/官方文档。

# python-smartdns

`python-smartdns` 是一个基于 Python 的异步 DNS 转发器，核心 DNS 处理使用
dnspython，并通过 Pydantic 配置、可插拔的上游 nameserver、规则分流和插件机制，
提供可扩展的本地智能 DNS 解析能力。

项目适合用于本地 DNS 代理、上游解析策略实验、规则化分流、缓存与响应改写等场景。
运行时可以同时监听 UDP/TCP DNS 请求，并按配置将查询转发到不同的上游解析器。

## 主要特性

- 支持多种上游协议：Do53、aiodns、DoT、DoH、DoQ、DNSCrypt，以及基于
  httpx、aiohttp、curl-cffi 的 DoH 客户端实现。
- 支持上游分组和调度策略，包括竞速返回和等待全部结果。
- 支持基于规则的请求分流，可按标签、查询类型等条件选择上游组或调度策略。
- 提供插件机制，可扩展缓存、查询日志、测速、拦截、IP 替换、IP 过滤、HTTPS
  记录处理、Cloudflare ECH 等功能。
- 使用单一 `config.json` 管理运行时、监听器、上游、规则、插件和 WebUI 配置。
- 内置 WebUI，可用于查看和保存配置，并支持手动 reload。

## 快速了解

示例配置见 [config.example.json](config.example.json)。可以先通过以下命令校验配置：

```bash
uv run python main.py --config config.example.json check-config
```

启动服务：

```bash
uv run python main.py --config config.example.json serve
```

## 架构文档

面向后续重构的处理流程、数据流、插件结构和风险点见
[docs/architecture.md](docs/architecture.md)。

简化版需求、功能说明和主处理流程见
[docs/requirements.md](docs/requirements.md)。

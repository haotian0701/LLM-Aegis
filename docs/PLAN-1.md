# 阶段 1：网关骨架与 Mock 本地 Provider

## 概要

交付一个不依赖本地模型或云端模型的可运行网关。有效请求固定产生 `LOCAL` 决策：默认 `strict` 模式因没有可信本地 Provider 而返回错误；显式启用 `demo` 模式后，可由 Mock 返回响应。真实敏感信息检测和策略阻断属于阶段 2。

## 实现

- **项目与运行环境**：采用已安装的 Python 3.13，同步修改产品 spec 中的版本要求。用 `pyproject.toml`、标准 `venv` 和 `pip` 管理依赖；接入 FastAPI、Pydantic v2、SQLAlchemy 2 Async、Alembic、psycopg 3、pytest、Ruff 和 Pyright。psycopg 3 支持 SQLAlchemy 的异步 PostgreSQL 引擎。[SQLAlchemy 文档](https://docs.sqlalchemy.org/en/20/dialects/postgresql.html#psycopg)
- **数据库**：保留 PostgreSQL，提供只启动数据库的 Compose 配置，应用在宿主机运行。首个迁移建立 `conversations` 和 `audit_events`：会话按 `(principal_id, conversation_id)` 隔离；审计分别保存策略动作、实际目的地、模拟标志、状态与错误，不保存原始消息。
- **接口**：实现阶段 0 约定的文本、非流式 `POST /v1/chat/completions` 子集。请求 ID、Bearer 鉴权、严格的请求校验、显式会话 ID 和统一错误格式进入同一处理链。用环境配置提供多个「主体 → API token」映射；未配置鉴权密钥、数据库地址或 Prompt HMAC 密钥时拒绝启动。
- **Provider 与审计**：定义异步 `ModelProvider` 接口。`MockLocalProvider` 返回固定的 Chat Completion 内容；超时和错误仅通过测试注入，不提供公开故障控制接口。模型调用前提交会话记录及派发前审计，调用后更新审计；写入失败时返回 `AUDIT_UNAVAILABLE`。`strict` 禁止加载 Mock，返回 `LOCAL_UNAVAILABLE`；`demo` 必须显式选择 Mock，审计记为 `actual_destination=MOCK`、`simulation=true`。阶段 1 不配置任何外部模型出口。
- **契约修正**：在阶段 0 文档中明确：鉴权失败、请求体无效或会话 ID 无效时，只返回请求 ID，不创建或回传会话 ID。有效请求的成功和 Provider 错误响应均回传会话 ID。

## 验证

- 用 ASGI 客户端验证有效请求的响应结构、两种会话 ID 来源、后续显式回传、未知字段和流式请求拒绝，以及鉴权失败；拒绝场景断言 Mock 未被调用。
- 用两个 API token 验证同文本会话 ID 的主体隔离；检查审计不含原始消息，Prompt Hash 使用服务端密钥计算。
- 注入 Mock 超时、Provider 错误及派发前审计失败，验证状态码、审计状态和无意外模型调用。
- Docker daemon 可用时，启动 PostgreSQL、运行 Alembic 升级并执行数据库集成测试；当前 Docker daemon 未运行，实施时需要先启动它。

## 既定边界

阶段 1 的有效请求固定为 `LOCAL`；`BLOCK`、`CLOUD`、`MASK_CLOUD` 的策略执行留到后续阶段。Mock 只验证网关链路，不代表真实语义检测或本地推理。使用 Python 3.13 和 PostgreSQL 是本次已确认的选择；计划不包含工期估算。

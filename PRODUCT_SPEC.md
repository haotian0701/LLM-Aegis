# Aegis 产品规格说明（MVP）

## 1. 产品定位

Aegis 是面向企业 LLM 应用的安全网关，部署在业务应用与本地或云端大语言模型之间。它提供 OpenAI Chat Completions 风格的统一接口，在模型收到请求前完成敏感信息检测、策略判断、必要的脱敏和模型路由，并记录可审计的安全决策。

核心目标是在尽量保持现有 AI 应用调用方式的同时，为企业提供模型访问控制、敏感信息保护、模型路由和审计能力。客户端不需要知道最终使用哪个模型提供商。

### 产品边界

Aegis 不是基础模型、RAG 系统、Agent Framework、身份认证平台或完整的企业 DLP 产品。MVP 聚焦于检测、策略、脱敏、路由和审计。

## 2. 对外接口与会话契约

### Chat Completions 接口

```text
POST /v1/chat/completions
```

接口采用 OpenAI Chat Completions 风格的请求和响应。客户端通过配置 Aegis 的 API Base URL 接入网关；Aegis 根据安全决策返回模型响应或阻断／错误响应。

### 会话 ID

- 会话 ID 由客户端显式传递，不根据 Prompt、消息内容或其他请求内容推断。
- 首次请求可以携带客户端已有的会话 ID；如果未携带，Aegis 生成新的会话 ID，并在响应中返回。
- 后续请求必须显式传回同一个会话 ID，才能沿用该会话的安全状态。未传 ID 的请求视为新会话。
- MVP 使用 `X-Aegis-Conversation-Id` 请求和响应头传递会话 ID，避免修改 Chat Completions 请求体。客户端提供的 ID 应在其认证范围内隔离，不能读取或覆盖其他客户端的会话状态。

**接入影响：**仅修改 Base URL 即可使用无状态网关能力；需要跨轮次安全状态的应用还须保存并回传会话 ID。

## 3. 请求处理流程

```text
业务应用
  → OpenAI-compatible API
  → Authentication
  → Conversation State
  → Security Detection（Regex / NER / Semantic Judge）
  → Risk Aggregation
  → Policy Engine
      ├─ BLOCK
      ├─ LOCAL
      ├─ MASK_CLOUD
      └─ CLOUD
  → 必要时脱敏
  → Model Router（Local / Cloud）
  → 必要时还原响应
  → Audit
  → 返回客户端
```

每轮安全检测覆盖请求中**全部 `messages`**，包括历史消息，而不是只检测最新一条用户消息。这样可以识别后续轮次重新携带的敏感上下文。检测结果与已有会话安全状态共同参与策略判断。

任何安全检测、策略判断、脱敏或模型调用失败都应形成可追踪的错误结果和审计记录。

## 4. 敏感信息检测

每个进入系统的模型请求经过分层检测：

| 检测器 | 识别对象示例 |
| --- | --- |
| 规则检测 | 邮箱、电话号码、IBAN、IP 地址、API Key、Secret |
| 命名实体识别（NER） | 人员、组织、地点 |
| 语义敏感度判断 | 企业机密、内部战略、并购信息、财务计划、未公开项目信息 |

各检测器输出统一的结构化发现，至少包含敏感信息类别、置信度、检测来源和在原文中的位置。Risk Aggregation 汇总发现并交给 Policy Engine；检测器本身不直接决定路由。

## 5. 策略引擎

Policy Engine 根据检测结果及会话状态，输出以下一种动作：

| 动作 | 行为 |
| --- | --- |
| `BLOCK` | 阻止请求，不发送给任何模型。 |
| `LOCAL` | 只发送给本地模型。 |
| `MASK_CLOUD` | 对敏感信息脱敏后发送给云端模型。 |
| `CLOUD` | 直接发送给云端模型。 |

策略由 YAML 等配置驱动。例如：

```yaml
default_action: cloud

rules:
  - category: API_KEY
    action: block
  - category: BUSINESS_SECRET
    action: local
  - category: IBAN
    action: mask_cloud
  - category: EMAIL
    action: mask_cloud
  - category: PERSON
    action: mask_cloud
```

同一请求命中多条规则时，选择更严格的动作：

```text
BLOCK > LOCAL > MASK_CLOUD > CLOUD
```

`default_action: cloud` 仅在安全检测及策略判断正常完成、且没有更严格规则或会话状态约束时适用。

## 6. 可逆脱敏

对于 `MASK_CLOUD` 请求，Aegis 在可信的本地环境中将需要保护的实体替换为稳定的占位符，并保存占位符与原始值的映射。云端响应返回后，Aegis 使用该映射还原响应中的占位符。

```text
原文：Please send the report to Max Müller.
云端：Please send the report to <PERSON_001>.
还原：The report for Max Müller has been summarized.
```

同一请求中的同一实体应使用一致的占位符。原始敏感值及其映射不得随脱敏后的请求发送给云端。若必须脱敏的实体无法可靠定位或替换，不能将原文作为 `MASK_CLOUD` 请求发往云端，应采用保守处理。

## 7. 模型路由

Aegis 使用统一的 Provider Abstraction 屏蔽模型提供商差异。MVP 包含：

- 本地 Provider：通过 Ollama 提供本地推理；接口预留 vLLM 和其他 OpenAI-compatible 本地推理服务。
- 云端 Provider：接入 OpenAI、OpenRouter 或其他 OpenAI-compatible 服务，通过 `base_url`、`api_key`、`model` 配置。

客户端只调用 Aegis；路由决策由策略引擎决定。

## 8. 会话安全状态

Aegis 为每个显式会话 ID 保存安全状态，包括是否已被标记为 `sensitive = true`。当会话因敏感内容进入敏感状态时，后续请求即使当前文本没有明显敏感信息，也可继续强制使用本地模型。例如：

```text
第 1 轮：普通内容             → CLOUD
第 2 轮：包含企业机密         → LOCAL，标记会话 sensitive = true
第 3 轮："Please summarize that." → LOCAL
```

会话状态与每轮对全部 `messages` 的检测同时生效：即使客户端在后续请求中省略了之前的敏感消息，只要使用同一会话 ID，已有的安全状态仍参与决策。

## 9. 故障保守处理

关键安全模块异常或结果不确定时，不能因此降级到云端：

| 情况 | 处理 |
| --- | --- |
| Semantic Judge 超时 | 转为 `LOCAL` |
| Policy Engine 异常 | 转为 `LOCAL` |
| 安全检测结果不确定 | 转为 `LOCAL` |
| 需要本地处理，但本地模型不可用或调用失败 | 返回错误，不改走云端；写入审计记录 |

任何无法确认原始敏感内容可安全发送到云端的情况，都不得选择直接云端发送。

## 10. 审计与数据存储

每次请求都生成安全审计记录；阻断请求和失败请求也需记录。审计内容至少包括：

```text
request_id
conversation_id
timestamp
检测到的敏感类别
最终策略
模型路由
模型 Provider
模型名称
是否脱敏
是否阻断
各检测模块耗时
总处理耗时
错误信息
```

默认不在审计记录中保存完整原始 Prompt，仅保存 Prompt Hash、Security Metadata 和 Decision Metadata，避免审计系统成为敏感信息泄漏点。

PostgreSQL 保存会话安全状态、安全决策、审计信息、脱敏映射和系统元数据。脱敏映射用于响应还原，其访问权限和保留期限应与普通审计元数据区分。

## 11. MVP 技术栈

| 领域 | 选型 |
| --- | --- |
| 后端 | Python 3.13、FastAPI、Pydantic v2、SQLAlchemy 2 Async、Alembic、PostgreSQL、httpx |
| 模型调用 | OpenAI Python SDK、OpenAI-compatible API、Ollama；vLLM 作为可选扩展 |
| 检测 | Python Regex、Presidio / spaCy、LLM-based Semantic Classifier |
| 配置 | YAML、Pydantic |
| 测试与质量 | pytest、pytest-asyncio、Ruff、Pyright |
| 基础设施 | Docker、Docker Compose、Linux |

可选的 Next.js / TypeScript 前端用于展示审计事件、路由决策、检测结果、策略配置和延迟指标；不属于核心请求链路的前置条件。

## 12. MVP 验收场景

1. 普通内容在检测和策略判断成功后，可按默认策略路由到云端。
2. 命中 `API_KEY` 的请求被阻断，不调用任何模型，并生成审计记录。
3. 命中 `BUSINESS_SECRET` 的请求仅进入本地模型。
4. 命中 `IBAN`、`EMAIL` 或 `PERSON` 且无更严格规则的请求，云端仅收到脱敏内容；响应中的占位符可在本地还原。
5. 同一请求同时命中多个类别时，按 `BLOCK > LOCAL > MASK_CLOUD > CLOUD` 选择动作。
6. 每轮检测请求中的全部 `messages`；复用显式会话 ID 时，已有安全状态继续参与路由。
7. 首次请求未传会话 ID 时，Aegis 生成并返回 ID；客户端已有 ID 可在首次请求中传入；Aegis 不根据内容推断会话归属。
8. 安全模块异常或判断不确定时请求仅可转本地；本地模型不可用时返回错误并审计，不能转云端。
9. 审计记录可追踪检测、决策、路由和耗时，默认不包含完整原始 Prompt。

## 13. 后续需细化的接口与策略细节

以下细节不改变上述 MVP 产品行为，但需要在实现设计中明确：

- OpenAI Chat Completions 兼容范围，尤其是流式响应、工具调用和多模态消息。
- 哪些敏感类别会使会话进入 `sensitive = true`，以及状态的有效期和重置方式。
- 语义检测器的部署位置与数据边界，确保检测环节本身不向未经授权的外部服务发送原始敏感内容。
- 脱敏映射的加密、访问控制、保留期限及响应还原失败时的处理。
- 客户端自带会话 ID 的格式、长度、认证范围及冲突处理。

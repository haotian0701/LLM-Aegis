# 阶段 0：接口与安全决策契约

状态：首版实现基线。依据 [产品规格](../PRODUCT_SPEC.md) 与 [阶段计划](../IMPLEMENTATION_PLAN.md)；实现中的例外须先更新本文件。OpenAI Chat Completions 原接口包含流式、工具和多模态能力，Aegis 首版明确只实现下述子集，避免未经检测的字段被透传。参考：[OpenAI 官方 Chat Completions API](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)。

## 1. 首版对外 API

### 请求

```text
POST /v1/chat/completions
Authorization: Bearer <aegis_api_token>
X-Aegis-Conversation-Id: <id>  # 可省略；省略时创建新会话
Content-Type: application/json
```

| 字段 | 首版行为 |
| --- | --- |
| `model` | 必填的客户端模型别名；真实 Provider 和模型由 Aegis 配置决定。 |
| `messages` | 必填的非空数组；支持 `system`、`developer`、`user`、`assistant`、`tool` 角色的纯文本 `content`。仅当历史 assistant 消息包含 `tool_calls` 时，其 `content` 可为 `null`。扫描数组中的每条消息，包括历史、system、tool 内容及历史 `assistant.tool_calls[].function.arguments`。 |
| `stream` | 省略或 `false`；`true` 明确拒绝。 |
| `temperature`、`top_p`、`max_tokens` | 可选；由 Aegis 验证范围并转换为 Provider 支持的参数。Provider 不支持时明确报错，不静默忽略。 |
| 顶层 `tools`、`tool_choice`，非文本 content、多模态字段及其他未知字段 | 首版明确拒绝，不发送给任何模型。工具消息及其对应的历史 `assistant.tool_calls` 可作为已完成的历史接受；本版不发起新的工具调用。 |

工具历史中的 `tool` 文本和对应的函数参数字符串同样检测；函数参数脱敏后还须保持有效格式。若客户端携带无法完整检测或安全替换的工具调用历史，整条请求拒绝。Aegis 不从拒绝的请求中提取部分文本再发送。

响应使用非流式 Chat Completion 基本结构：`id`、`object=chat.completion`、`created`、客户端模型别名、`choices[0].message`、`finish_reason`，以及 Provider 可提供时的 `usage`。Aegis 的会话 ID 只放在响应头，不插入标准响应体。请求和响应中的 `model` 是逻辑别名，实际 Provider 与模型记录在审计中。

### 错误与响应头

所有响应都返回 `X-Aegis-Request-Id`。鉴权失败、请求体无效、模型别名无效或会话 ID 无效时，不建立会话，也不返回会话 ID。完成鉴权和校验的有效请求无论成功、策略阻断还是模型故障，都返回 `X-Aegis-Conversation-Id`。

错误体统一为：

```json
{
  "error": {
    "message": "Human-readable explanation",
    "type": "aegis_error",
    "code": "AEGIS_ERROR_CODE",
    "request_id": "..."
  }
}
```

| 情况 | HTTP 状态 | 代码 |
| --- | --- | --- |
| 请求格式或功能不支持 | `400` | `INVALID_REQUEST` / `UNSUPPORTED_FEATURE` |
| 鉴权失败 | `401` | `UNAUTHORIZED` |
| 策略阻断 | `403` | `POLICY_BLOCKED` |
| 可信本地 Provider 未配置或不可用 | `503` | `LOCAL_UNAVAILABLE` |
| 安全判断无法完成且不能安全处理 | `503` | `SECURITY_UNAVAILABLE` |
| 上游 Provider 错误 | `502` / `504` | `PROVIDER_ERROR` / `PROVIDER_TIMEOUT` |
| 审计持久化失败 | `503` | `AUDIT_UNAVAILABLE` |

错误正文不得包含原始敏感片段或脱敏映射。API Key 只用于认证 Aegis；云端 Provider 凭据由服务端配置，不接受客户端在请求中指定实际 Provider 地址或密钥。

## 2. 会话 ID 与状态

1. 客户端可在首次请求显式提供 `X-Aegis-Conversation-Id`；未提供时，Aegis 生成不易猜测的 ID，并在响应头返回。
2. 每次未提供 ID 的请求都是新会话。Aegis 绝不根据内容、模型名或时间邻近性推断会话归属。
3. 会话状态以 `(authenticated_principal, conversation_id)` 为键。不同主体使用相同文本 ID 时状态隔离；任何主体不能读取或覆盖另一个主体的状态。
4. ID 只允许可安全放入 HTTP 头的有限长度字符；空值、超长值及控制字符拒绝。具体长度上限在实现配置中固定并测试。
5. 会话一旦升级为 `sensitive=true`，首版不自动降级。客户端通过新的会话 ID 开始新的状态；自动过期和管理端清理留待后续设计。

**建议的首版升级规则：**检测到 `BUSINESS_SECRET`、`API_KEY` 或 `SECRET` 时升级会话。`EMAIL`、`IBAN`、`PERSON` 可走 `MASK_CLOUD`，不因这些类别本身自动升级。升级类别做成策略配置，实施前用合成样例验证。`BLOCK` 请求若含升级类别，也要先保存敏感会话状态再返回阻断响应。

## 3. 运行模式及真实目的地

| 模式 | `LOCAL` 决策 | 安全组件失败 | 无可信本地 Provider |
| --- | --- | --- | --- |
| `strict`（默认） | 只调用配置的可信自部署 Provider | 尝试 `LOCAL`；本地不可用则错误 | 错误并审计 |
| `demo`（显式开启） | 可调用 Mock；也可显式使用外部 API 模拟 | 直接错误并审计，不转向模拟外部 API | 仅在显式配置模拟 Provider 时可演示 |

模式在服务启动时配置，不能由单个请求通过 header 或 body 切换。`demo` 模式的模拟 Provider 必须记录 `policy_action=LOCAL`、`actual_destination=EXTERNAL`、`simulation=true` 和实际 Provider 标识；对外示例与 UI 必须标明这是云端模拟。`strict` 模式不得加载 `SimulatedLocalProvider`。

语义检测器也有独立的数据边界：首版可用确定性的测试实现验证链路；测试实现的结果不能声明为真实语义检测。若 `demo` 模式后来接入云端语义分类器，应在审计中记录检测请求的外部去向，并且仅用合成数据演示。`strict` 模式不把原始消息交给未授权的外部分类服务。

## 4. 安全决策顺序

```text
验证请求与鉴权
→ 确定显式会话 ID、读取会话状态
→ 扫描全部 messages
→ 汇总检测结果
→ 校验并执行策略（BLOCK > LOCAL > MASK_CLOUD > CLOUD）
→ 在同一事务中持久化会话状态升级及派发前审计
→ 根据模式及动作确定真实目的地
→ 必要时脱敏、发送、还原
→ 更新审计并返回
```

在任何模型调用前，必须成功提交会话状态变化及派发前审计。若事务失败，直接返回错误。模型调用后的审计更新也应在响应前完成；更新失败时返回审计错误，留下已有的派发前记录供排查。默认不保存原始 Prompt；Prompt Hash 使用服务端密钥计算的 HMAC，避免低熵文本被普通哈希轻易匹配。

## 5. 决策表

`LOCAL` 列表示策略动作；真实目的地还要受运行模式约束。以下表格中的检测结果均指对全部 `messages` 扫描后的结果。

| 输入或故障 | 策略动作 | `strict` 真实行为 | `demo` 真实行为 |
| --- | --- | --- | --- |
| 无发现且会话不敏感，检测全部成功 | `CLOUD` | 直接云端 | 直接云端 |
| 发现 `API_KEY` | `BLOCK` | 不调用模型；升级会话；审计 | 同左 |
| 发现 `BUSINESS_SECRET` | `LOCAL` | 可信本地；无则错误 | 可显式模拟外部调用，并如实标记；否则 Mock 或错误 |
| 仅发现 `EMAIL` / `IBAN` / `PERSON` | `MASK_CLOUD` | 成功脱敏后云端 | 同左 |
| 同时发现 `BUSINESS_SECRET` 与 `EMAIL` | `LOCAL` | 可信本地；无则错误 | 显式模拟、Mock 或错误；不按 `MASK_CLOUD` 发送 |
| 同时发现 `API_KEY` 与任何其他类别 | `BLOCK` | 不调用模型 | 不调用模型 |
| 旧会话已为 `sensitive=true`，本轮无新发现 | `LOCAL` | 可信本地；无则错误 | 显式模拟、Mock 或错误 |
| 检测器超时、结果不确定、Policy Engine 异常 | 保守处理 | `LOCAL`；无本地则错误 | 直接错误，不调用模拟外部 API |
| 必须脱敏但无法可靠定位、替换或验证 | 保守处理 | `LOCAL`；无本地则错误 | 直接错误，不外发原文 |
| `LOCAL` Provider 不可用 | `LOCAL` | 错误并审计，不转云端 | Mock / 模拟 Provider 故障则错误，不自动换其他外部 Provider |
| 云端 Provider 不可用 | `CLOUD` / `MASK_CLOUD` | 错误并审计，不自动改路由 | 同左 |
| 审计无法持久化派发前记录 | 任意 | 错误，不调用模型 | 同左 |
| 请求含不支持的消息或字段 | 无 | `400`，不调用模型 | 同左 |

## 6. 阶段 0 交付与后续验证

本文件是阶段 0 的接口契约和决策基线。后续阶段需把决策表变成可执行测试：用假 Provider 记录实际入站请求，断言阻断与故障场景没有意外的模型调用；同时验证审计中的策略动作与真实目的地分别正确。

**仍需在实现时量化的参数：**会话 ID 长度上限、请求体大小、检测超时、置信度阈值、HMAC 密钥轮换、脱敏映射保留期限。它们可通过配置确定，但不得改变上面的路由与外发边界。

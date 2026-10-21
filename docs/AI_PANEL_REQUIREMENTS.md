# AI Copilot 面板需求分析与功能规划（GitHub Copilot 风格多会话）

> 本文是对「参考 GitHub Copilot 布局：模型/模式/会话切换选择 + 记忆/技能/MCP 配置 +
> 新建会话、多会话并行、挂起后台运行、历史会话管理」这一需求草案的**完善版需求说明**：
> 先给出清晰度评估与缺失项，再钉死关键设计决策，最后输出带边界、交互、优先级与
> 验收标准的功能规格，可直接进入开发排期。
>
> **评审状态：§7 的 5 个开放问题已于 2026-10-21 定稿（见文末决策记录），可直接进入排期。**
>
> 现状基线见 [AI_COPILOT.md](AI_COPILOT.md)：现有抽屉是**每终端标签一个单会话**
> （`ui/ai_panel.slint`，挂载于 `ui/terminal_view.slint` 的 overlay；Rust 侧状态为
> `src/app/ai.rs` 的 `TabAi`），`TriageEngine` 每轮新建、无跨轮历史
> （`crates/ai-copilot/src/triage.rs`），技能只能手改 `sessions.json`
> （`ai_skills` 字段），无会话列表、无历史持久化、无记忆。

---

## 1. 需求清晰度评估

**结论：当前描述尚未形成清晰、可开发的需求，属于「功能愿望清单」——有 What，缺 How、
边界、优先级与验收标准。** 已可保留为基线的事实：

- 模式切换（Ask / Agent）已存在，安全基线（Run Gate 四道墙、风险分级、180s 审批超时）
  已存在，新功能**不得绕过**。
- 设置存 `sessions.json` 的 `ai_*` 字段，API Key 用 ChaCha20-Poly1305 加密。

必须补齐的 8 个缺口：

| # | 缺口 | 风险 |
|---|---|---|
| 1 | **AI 会话与终端标签的关系未定义**。AI 依赖终端上下文（OSC 133 块 / 8KB 窗口），「多会话并行」与「一个 tab 一个 PTY」如何共存？ | 架构级：决定面板是 per-tab overlay 还是全局 dock |
| 2 | **「挂起」语义未定义**。切走标签？关闭面板？退出应用？退出后重启是否恢复？进行中的轮次怎么办？ | 决定持久化范围与恢复语义 |
| 3 | **「记忆」零定义**。存什么、存哪、怎么注入、安全边界？ | 代码库完全空白，易做成品混杂的「自动记忆」 |
| 4 | **「MCP 配置项」指向不明**。项目已有内置 MCP Server（`docs/REMOTE_MCP.md`），是指配置**外部 MCP server 作 client**，还是管理内置 server 的开关？两者工作量差一个数量级 | 范围爆炸风险 |
| 5 | **「模型切换」粒度未定义**。全局当前模型 vs 会话创建时锁定；运行中的会话能否改模型 | 影响消息历史与协议兼容 |
| 6 | **无交互细节**。面板停靠位置、快捷键、会话列表形态、空态、进行中指示 | 无法进入 UI 实现 |
| 7 | **无优先级与分期** | 无法排期 |
| 8 | **无非功能约束**。并发上限、同终端并发写冲突、消息条数/体积上限、落盘敏感级 | 稳定性与安全风险 |

---

## 2. 关键设计决策（先把边界钉死）

### D1 面板形态：全局 dock 面板 + 会话锚点（取代 per-tab 抽屉）

- AI 面板从 `TerminalView` 内 overlay **提升为应用级右侧停靠面板**（两档 360/520px，
  默认 360px，选择持久化到 `sessions.json` 的可选字段 `ai_panel_width`；不做拖拽），
  `Ctrl+Space` 开关。理由：需求要求「会话挂起后台运行 + 切换会话看进度」，
  会话生命周期必须独立于终端标签的可见性；GitHub Copilot Chat 本身也是独立面板。
- **每个会话有且仅有一个「锚点 tab」**（创建时绑定当前终端标签；也允许创建无锚点的
  纯对话会话）。锚点决定该会话的终端上下文来源（块窗口、命令执行写入的 PTY）。
- **迁移策略**：旧 per-tab 抽屉废弃，不保留双 UI。**现状对话不落盘**（`TabAi.messages`
  仅在内存，Slint 的 `ai-messages` 只是镜像，见 `src/app/ai.rs`），进程退出即丢，
  因此升级后不存在可迁移的历史：首次启动按需为终端 tab 惰性创建**空**锚点会话，
  不伪造历史。从本版本起，会话历史才由 `ai_conversations.json` 承接。
- `Ctrl+Space` 语义：打开面板并聚焦当前 tab 的锚点会话；无则打开/新建默认会话。

### D2 挂起与退出的语义

| 场景 | 语义 |
|---|---|
| 切换终端标签 / 切换会话 / 关闭面板 | **挂起**：LLM 轮次继续在后台运行，消息持续写入 Rust 侧会话状态，切回即重放（复用现有 `resync_conversation` + `generation` 机制） |
| 退出应用 | 所有会话的本轮**取消**（与现有「停止」同语义：引擎下一回合边界退出、流式分片丢弃），无后台驻留 |
| 重启后恢复 | 历史会话以 `interrupted` 状态恢复；进行中的轮次标记为中断，**pending 审批卡片一律作废**（审批通道 `oneshot` 是进程内对象，不可跨进程） |

### D3 并发模型

- 同时**运行中**的会话上限默认 3（设置可调 1–5）。并发已满时新会话的发送按钮禁用并
  提示，不排队、不静默丢弃。
- **同一锚点 tab 的命令执行串行化**（tab 级执行锁）：两个会话同时往同一 PTY 写命令 +
  装 sentinel 会互相踩。持锁失败的一方本轮降级为「只读取证 / 文本建议」，UI 明示。
- 每会话独立 `TriageEngine` 实例 + 独立 `cancel` 开关（现有机制），互不共享状态；
  进程级共享的仅补全缓存与审计日志（保持不变）。

### D4 持久化范围

- 新文件 `ai_conversations.json`（数据目录，与 `sessions.json` 同级，同样按敏感文件
  保管、同样文件权限）：会话元数据 + 全量消息（含命令卡片、Agent 计划与步骤痕迹）。
  不存 API Key。
- 写盘策略：每轮结束防抖 500ms 批量写 + 退出时 flush；**不逐 token 写盘**。
- 保留上限：默认最近 100 个会话，超出淘汰最旧（可在设置关闭上限）。
- 导出：会话可导出为脱敏后的 Markdown / 文本（与 audit log 导出同等敏感级提示）。

### D5 「记忆」的界定（本期范围）

- 记忆 = **用户显式管理的跨会话事实/偏好**（如「生产集群禁执行 kubectl delete」），
  全局单列表，`enabled` 开关，注入所有会话的 system prompt 前置，可按会话关闭。
- 写入方式（P1）：管理 UI 手动增删改 + **AI 提议卡片**（与命令卡片同款审批模式，用户
  确认才落库）。**不做**无提示的自动提炼（P2 再评估）。
- 安全：记忆内容进 prompt 前过脱敏规则；一键全删；随会话导出。

### D6 「MCP 配置项」的界定（分期）

- **P1（配置面）**：设置页暴露**内置 MCP Server** 的现有开关与权限
  （`mcp_enabled` / `mcp_allow_commands` / `mcp_allow_file_transfers` 等，见
  `docs/REMOTE_MCP.md`）与文档入口。零新协议代码。
- **P2（能力面，需独立 RFC）**：AI 作为 **MCP client** 配置外部 server
  （stdio / SSE / Streamable HTTP）、工具发现与调用审批。默认关闭，调用走 Run Gate。
  本期明确 **OUT**：MCP resources / roots / sampling / 自动安装。

---

## 3. 功能需求规格

> 每个功能给出：边界（IN / OUT）、交互方式、验收标准、优先级。
> P0 = 多会话骨架（消除最大缺口）；P1 = 管理闭环；P2 = 扩展。

### F1 布局重构：Copilot 风格全局面板 ★P0

- **IN**：右侧 dock 面板（两档宽度 360/520px，默认 360px，选择持久化）；头部栏 = 星标 + 会话标题
  （点击展开会话列表）+ 模型 chip + 模式 chip（Ask/Agent）+ 设置齿轮 + 关闭；
  中部对话流（复用现有消息渲染：用户气泡 / 助手文本 / 命令卡片 / 计划清单 / 步骤痕迹 /
  错误条）；底部输入区 + Send/Stop。
- **OUT**：可拖拽分隔条、多面板并排、底部停靠、主题差异化。
- **交互**：`Ctrl+Space` 开关面板；Esc 关闭会话列表 popover 不关面板；
  面板停靠时终端区自动收缩，不遮挡。
- **验收**：
  1. 面板打开/关闭不中断任何运行中的会话（消息继续累积，重开后内容完整）。
  2. 旧版本升级后不残留 per-tab 抽屉 UI；打开面板时按当前 tab 惰性创建空锚点会话，
     不展示伪造的旧消息（现状对话未落盘，此项明确不做数据迁移）。
  3. 面板常驻时终端多标签切换、htop 全屏渲染无回归（现有 tests 全绿）。
  4. 切到 520px 档后重启应用，面板仍为 520px（`ai_panel_width` 持久化生效）。

### F2 模型管理与会话级模型选择 ★P1

- **IN**：设置页管理**多份模型配置**（name / protocol / endpoint / model / API Key，
  Key 沿用现有加密只写语义），其中一份为默认；面板头部模型 chip 展示当前模型，
  点击弹出列表切换；**会话创建时快照 `model_ref` 并锁定**。
- **OUT**：会话内多模型混合调用、模型能力自动探测（如上下文长度）。
- **交互**：切换模型只影响「当前全局选择 / 新会话默认」；运行中会话的模型锁定，
  其 chip 显示锁定标识且不可改。
- **约束**：不同 protocol 的配置互不混用；列表显示「默认」标记与脱敏端点。
- **验收**：
  1. 会话 A 用模型 X 运行中，全局切到模型 Y，会话 A 后续请求仍走 X（审计日志验证）。
  2. 新会话默认继承全局当前模型；模型列表含 Test connection（复用现有自检）。

### F3 模式切换升级为会话级 ★P1

- **IN**：Ask/Agent chip 移至会话级；运行中切换只影响**后续轮次**的系统提示与回合
  预算（Ask=2 / Agent=6），当前轮次不受影响，切换时 toast 明示。
- **OUT**：新增第三种模式、按消息粒度混合模式。
- **约束**：现有全局 `ai_mode` 保留为「新会话默认模式」；模式语义与 Run Gate 完全不变
  （Agent 不绕过审批）。
- **验收**：
  1. Agent 会话运行中切到 Ask，下一轮工具回合上限为 2（引擎配置断言 + UI 提示）。
  2. 模式 chip 状态随会话切换正确重放（切到 Agent 会话显示 Agent）。

### F4 会话管理：新建 / 切换 / 并行 / 挂起 / 恢复 ★P0

- **IN**：
  - 新建：面板头部「+」或 `Ctrl+Shift+O`（macOS `⌘⇧O`）——`Ctrl+Shift+N` 已被
    「新建窗口」占用（`ui/terminal_view.slint` 的 key handler、`ui/app.slint` 快捷键表），
    故改用 O；在窗口层注册并拦截，不落入 PTY，同时补进快捷键帮助表。创建时绑定当前
    tab 为锚点；空标题占位「New conversation」。
  - 会话列表：头部标题点击展开 popover —— 每行显示标题、锚点 tab 名、状态点
    （running 脉冲 / interrupted / idle）、更新时间；底部「新建会话」。
  - 切换：点击即切，本地数据重放，**< 100ms**；运行中会话切回自动滚到底部并显示 Stop。
  - 关闭会话：列表项 hover 出「×」，二次确认（运行中需先停止或确认取消）。
- **OUT**：会话内部分支（fork）、会话分组/标签、跨窗口拖拽会话。
- **约束**：
  - 并发运行上限 3（可配置 1–5），满时发送禁用 + 提示；
  - 同锚点命令执行串行化（见 D3），降级方 UI 明示「另一会话正在该终端执行」；
  - 锚点 tab 被关闭：会话保留，锚点标记失效，后续轮次以无终端上下文运行并提示；
  - 标题默认取首条用户消息前 30 字，可重命名（P1 随 F6 落地，P0 先只读默认标题）。
- **验收**：
  1. 并发 3 个会话并行运行，逐个切换均能在 2s 内看到各自最新流式输出与计划清单状态。
  2. 关闭面板 5 分钟后重开，运行中会话 continued，消息无丢失、无重复。
  3. 同一锚点两个会话同时请求执行命令，第二个被串行化并得到明确提示。
  4. 第 4 个会话发送时按钮禁用并提示并发已满。
  5. 终端聚焦时按 `Ctrl+Shift+O` 新建锚定当前 tab 的会话，远端 shell 收不到任何字符
     （key handler 已拦截）；快捷键帮助表可见该条目。

### F5 后台运行与进度可视化 ★P0

- **IN**：会话列表项状态点（脉冲动画）；会话内底部运行指示（流式光标 + Stop）；
  Agent 计划清单与步骤痕迹随切换重放且状态最新；Stop 语义与现有 `cancel` +
  `generation` 一致（已生成文本丢弃、审计日志保留）。
- **OUT**：后台运行的系统级通知（P2）、跨设备的运行状态同步。
- **交互**：切到运行中会话自动滚底；用户手动上滚时不强制拉回（仅在切回瞬间滚底一次）。
- **验收**：
  1. 会话挂起期间发生的全部消息（流式增量、卡片、步骤、审批请求）在切回后完整呈现。
  2. Stop 后会话回到 idle，卡片 pending 项保留可操作，审计日志含中止记录。

### F6 历史会话查看与管理 ★P1

- **IN**：退出即持久化（`ai_conversations.json`，D4）；会话列表支持按更新时间排序 +
  标题/消息全文搜索；重命名、删除（二次确认）、导出（脱敏 Markdown）；恢复的
  interrupted 会话可继续提问（其 pending 卡片已作废，卡片置灰显示 expired）。
- **OUT**：会话分享链接、云端同步、导入第三方格式、JSONL 机读导出（M3 再评估，
  避免在 `AiMessage` 结构稳定前冻结对外 schema）。
- **约束**：落盘前消息过脱敏规则（复用 `redact`）；导出文件按敏感文件管理；
  保留上限 100（可关）。
- **验收**：
  1. 退出应用重启，全部会话可检索、可打开，状态为 interrupted，无 pending 卡片可点。
  2. 搜索「502」命中含该关键词的历史会话（标题或消息）。
  3. 导出的 Markdown 中不出现内网 IP / `sk-` 密钥等脱敏规则命中内容（测试用例构造）。

### F7 记忆（Memory）配置 ★P1

- **IN**：设置页 AI Copilot 下的「记忆」分区：列表（内容 / 来源 manual|ai-proposed /
  时间 / 启用开关）、新增、编辑、删除、一键清除；AI 提议卡片（用户确认写入）；
  会话级开关（该会话是否注入记忆，默认开）。
- **OUT**：自动提炼记忆、记忆版本历史、跨设备同步。
- **约束**：注入 system prompt 前置且过脱敏；总量上限 50 条 / 单条 500 字（防 prompt
  膨胀）；审计日志记录记忆写入事件（记来源不记全文）。
- **验收**：
  1. 新增记忆「生产集群禁 kubectl delete」后，新会话的 system prompt 含该条
    （单测断言）；关闭开关后不再注入。
  2. AI 提议卡片确认后出现在列表，拒绝后不出现且不留空引用。

### F8 技能（Skills）管理 UI ★P1

- **IN**：设置页技能分区：列表（name / id / description / 启用开关）、新建、编辑、
  删除；表单校验（id 唯一且不为 `general`、content ≤ 8KB）；保存即写
  `sessions.json` 的 `ai_skills`。
- **OUT**：技能市场/导入 URL、技能版本管理。
- **约束**：保持现有「会话启动时快照进引擎，中途修改不影响运行中轮次」语义；
  `general` 内置集始终展开、不可删。
- **验收**：
  1. UI 新建技能后无需重启，下一轮对话的 system prompt 目录含该技能（load_skill 可拉到全文）。
  2. id 填 `general` 或重复 id 时保存被拒并给出原因。

### F9 MCP 配置项 ★P1（配置面）/ P2（外部 client）

- **P1 IN**：设置页 MCP 分区：内置 MCP Server 开关与权限矩阵
  （enabled / allow_commands / allow_file_transfers / use_saved_credentials）+
  指向 `docs/REMOTE_MCP.md` 的说明链接；状态显示（stdio 模式地址 / HTTP 模式端口）。
- **P2 IN**：外部 MCP server 管理（添加 stdio/SSE/HTTP server、连通性测试、工具列表）、
  工具调用走审批卡片。
- **OUT（两期共同）**：resources / roots / sampling、自动安装 server、server 市场。
- **验收（P1）**：开关改动落盘 `sessions.json` 对应字段；关闭后 `mcp serve` 拒绝连接
  （现有行为回归）。

---

## 4. 数据模型（新增）

```jsonc
// data_dir/ai_conversations.json  （按敏感文件保管，权限同 sessions.json）
{
  "version": 1,
  "active_id": "uuid",
  "conversations": [
    {
      "id": "uuid",
      "title": "nginx 502 排查",
      "anchor_tab": "tab-id | null",      // 锚点终端；tab 关闭后保留原值 + anchor_lost: true
      "anchor_lost": false,
      "mode": "ask | agent",
      "model_ref": "默认模型",             // 创建时快照，运行中不变
      "memory_enabled": true,
      "status": "idle | running | interrupted",
      "created_at": "rfc3339",
      "updated_at": "rfc3339",
      "messages": [ /* AiMessage 全量：role 0..5，含 card-id/risk/gate/disposition/step-state */ ]
    }
  ]
}
// sessions.json 增量（均为可选字段，旧版兼容）
"ai_model_profiles": [ { "name": "...", "protocol": "...", "endpoint": "...", "model": "...",
                         "api_key": "<Secret>", "default": true } ],
"ai_memory": [ { "id": "uuid", "content": "...", "source": "manual | ai-proposed",
                 "enabled": true, "created_at": "rfc3339" } ],
"ai_max_parallel": 3,
"ai_panel_width": 360                  // 360 | 520，面板宽度档位
```

- `AiMessage` 由 Slint 生成（`slint::include_modules!`），**不能直接加 `serde` 派生**；
  新增 Rust 侧持久化 DTO（如 `StoredMessage`）做双向转换。恢复时 `card-id` 保留、
  `disposition: pending` → `"expired"`。
- 单会话上限：500 条消息 / 4MB 文本，超限淘汰最旧的**非卡片**消息（卡片是审计痕迹，
  不参与淘汰）。

---

## 5. 非功能需求与约束汇总

| 类 | 约束 |
|---|---|
| 安全 | 会话文件与导出按敏感文件管理；恢复的 pending 卡片作废；同锚点执行串行化；记忆与 skill 内容过脱敏；新功能不得绕过 Run Gate 四道墙；外部 MCP 默认关闭 |
| 性能 | 切会话 UI < 100ms；10 个会话常驻面板内存增量 < 20MB；持久化防抖批量写不逐 token 落盘；并发运行上限默认 3 |
| 兼容 | `sessions.json` 新字段全部可选；旧 per-tab 对话不迁移（现状未落盘，见 D1）；`Ctrl+Space` 行为变更需在 CHANGELOG 与设置提示 |
| 可观测 | 复用现有审计日志：新增事件点（会话创建/切换/恢复、并发拒绝、串行化降级、记忆写入、模型锁定切换） |
| 质量 | 每个 P0/P1 功能附验收标准（见 §3）；核心路径补单测（串行化锁、并发上限、迁移、脱敏导出） |

---

## 6. 分期路线图

| 里程碑 | 范围 | 出口标准 |
|---|---|---|
| **M1（P0）多会话骨架** | F1 布局重构 + D1/D2/D3/D4 决策落地 + F4 会话管理 + F5 后台进度 + 旧抽屉下线 | 可演示：3 会话并行、切回 2s 内见进度、关面板不中断、重启恢复 interrupted、宽度档位保持；现有 tests 全绿 |
| **M2（P1）管理闭环** | F2 模型管理 + F3 会话级模式 + F6 历史管理 + F7 记忆 + F8 技能 UI + F9-P1 内置 MCP 开关 | 技能/记忆零手改 JSON；历史可搜索可导出；模型按会话锁定可验证 |
| **M3（P2）扩展** | F9-P2 外部 MCP client（独立 RFC 先行）、记忆自动提炼评估、会话导出格式增强、LLM 自动命名 | 另立需求文档评审 |

---

## 7. 决策记录（2026-10-21 评审定稿）

原列的 5 个开放问题已全部定稿，不阻塞 M1 开工：

| # | 问题 | 决策 | 理由 / 影响 |
|---|---|---|---|
| 1 | 面板宽度 | 固定两档 **360 / 520px，默认 360px**，选择持久化到 `sessions.json` 的 `ai_panel_width`；**不做拖拽** | 默认窄档优先保终端可视面积，长命令卡片可切宽档；拖拽涉及连续宽度状态与终端重排，收益低，留待反馈再加且不破坏 schema |
| 2 | 新建会话快捷键 | **`Ctrl+Shift+O`（macOS `⌘⇧O`）** | 已核实 `Ctrl+Shift+N` 被「新建窗口」占用（`ui/terminal_view.slint` key handler、`ui/app.slint` 快捷键表）；O 在现有键位表中空闲。需在窗口层注册并拦截，避免落入 PTY |
| 3 | 并发上限 | **固定默认 3，可在设置中调 1–5**；不按 CPU 核数自适应 | 并发瓶颈是 LLM 网络等待而非 CPU，自适应会增加不可预期行为与支持成本；M3 依据使用数据再评估 |
| 4 | 导出格式 | **P1 只做脱敏 Markdown**；JSONL 机读导出列为 M3 可选项 | 避免在 `AiMessage` 结构稳定前冻结对外 schema；Markdown 已满足工单/复盘粘贴需求 |
| 5 | 外部 MCP client | **仅登记为 M3 候选，不进入当前承诺范围**；启动前须有独立 RFC（传输、鉴权、工具审批映射到 Run Gate、资源上限） | 与 F9 的 P2 定位一致，避免范围爆炸；先观察内置 MCP 的使用数据 |

> 已回写：D1 / F1（宽度与默认值）、F4（快捷键）、F6（JSONL 出范围）、§4（`ai_panel_width` 字段）。

---

## English summary

This document upgrades the draft requirement ("GitHub Copilot-style panel: model/mode/
session switching, memory/skills/MCP config, multi-session parallel + suspend/resume,
history management") into an actionable spec. Verdict: the draft is a wish-list; 8 gaps
(binding between conversations and terminal tabs, suspend semantics, memory, MCP scope,
model granularity, interactions, priorities, NFRs) must be closed first. Key decisions:
global right-dock panel with per-conversation "anchor tab"; suspend = UI detach while the
round keeps running; app exit cancels rounds and restores conversations as `interrupted`
with expired approval cards; at most 3 concurrently running conversations with
per-anchor serialized command execution; persistence in `ai_conversations.json` (the
current build keeps conversations in memory only, so no legacy migration is attempted,
and a separate serde DTO mirrors the Slint message type); memory =
explicit user-managed facts injected into the system prompt (manual + AI-proposed cards);
MCP split into P1 config surface for the built-in server and a P2 external-client RFC.
Delivered as three milestones (M1 multi-session skeleton, M2 management closure,
M3 extensions) with per-feature acceptance criteria. The five open questions are
resolved: two-tier 360/520 px panel with no drag, `Ctrl+Shift+O` for a new
conversation (since `Ctrl+Shift+N` opens a new window), fixed concurrency default
3, Markdown-only export in P1, and external MCP as an M3 candidate pending an RFC.

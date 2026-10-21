# AI 面板 M1 实施拆解（多会话骨架）

> 对应 [AI_PANEL_REQUIREMENTS.md](AI_PANEL_REQUIREMENTS.md) 的 **M1 / F1 / F4 / F5**。
> 本文只回答「怎么落」：目标架构、工作包、PR 切片、测试与风险；不重复需求背景。
> 范围外：F2 模型多配置、F3 会话级模式、F6 历史搜索、F7 记忆、F8 技能 UI、F9 MCP。

---

## 0. 现状与目标的差距

| 维度 | 现状 | M1 目标 |
|---|---|---|
| 会话归属 | `TabAi` 挂在 `TabRoute` 内（`src/app/session_runtime.rs:117`），随 tab 销毁 | `ConversationStore` 挂在 `AppCore`，会话独立于 tab 生命周期 |
| 消息镜像 | 每个 tab 一份 `TerminalState.ai_messages`（`ui/app.slint:86`） | 窗口级 `ai-messages` + `ai-active-id`，只镜像当前查看的会话 |
| 面板位置 | `TerminalView` 内 overlay（`ui/terminal_view.slint:2457`） | `ui/app.slint` 应用级右侧 dock，终端区收缩 |
| 持久化 | 无；`TabAi.messages` 仅内存 | `ai_conversations.json`（0600、原子写、500ms 防抖） |
| 并发 | 每个 tab 各自一轮，无全局上限 | 运行中会话上限 3（可调 1–5） |
| 审批通道 | `TabAi.approval`（`src/app/ai.rs:92`） | 移到 `Conversation`，按会话 id 应答 |
| 终端执行 | 对话与 PTY 执行绑定在同一个 `TabAi` | 抽成 `TabContext`，按锚点解析；同锚点串行化 |

**已确认的现状限制**：旧对话没有落盘，升级无法迁移（见需求文档 D1）。M1 不写迁移代码，
也不保留旧抽屉双 UI。

---

## 1. 目标结构

```text
AppCore
├─ conversations: Arc<Mutex<ConversationStore>>     // 进程级、跨线程
│    ├─ Vec<Conversation>                           // 消息/状态/锚点/模式/模型快照
│    └─ ai_conversations.json 防抖落盘
├─ tab_routes: TabRoutes
│    └─ TabRoute { context: Arc<Mutex<TabContext>>, ... }
│         └─ TabContext { parser, blocks, exec, exec_lock }   // 终端侧只读上下文 + 执行态
└─ window_states
     └─ WindowState { ai_open, ai_active_id, ai_messages(model), ... }  // 每窗口的 dock 视图

UiRuntime {
    conversation: ConversationHandle,   // 消息、审批、cancel、generation
    anchor: Option<Anchor>,            // tab-id → 命令通道 / session / TabContext
    weak_window,
}
```

### 实施级决策（本计划拍板）

- **D7 会话存 `AppCore`，dock 选中态存 `WindowState`**。理由：`ai_conversations.json` 只有
  一份，会话要能跨窗口存活；锚点 tab 被拖到另一个窗口时，会话不迁移、只重新解析锚点。
- **D8 终端上下文仍按 tab 保存，会话每轮开始时取快照**。同一锚点的多个会话共享
  `TabContext`（块窗口、执行捕获），但各自持有独立的消息、审批与 `cancel`。
- **D9 流式增量只写 Rust store，按可见性刷 UI**。仅当某窗口正在查看该会话时才
  `invoke_from_event_loop`；连续增量按 ~50ms 合并，避免后台会话每 token 克隆整份消息。
  现有 `with_messages` 的「每次全量 clone + 重建 VecModel」不能直接沿用到多会话。

---

## 2. 工作包

### WP1 会话模型与拆分 `TabAi`

- 新增 `src/app/ai_store.rs`：
  - `Conversation { id, title, anchor_tab, anchor_lost, mode, model_ref, memory_enabled,
    status, created_at, updated_at, messages, busy, generation, cancel, approval }`；
  - `ConversationStatus { Idle, Running, Interrupted }`；
  - `ConversationStore { version, active_id, conversations }` + 内存版增删查、运行中计数、
    上限淘汰（本工作包不落盘）。`active_id` 仅作「新窗口默认选中」的回退，实际选中态
    每窗口一份存在 `WindowState.ai_active_id`。
- `TabAi` 改名为 `TabContext`，保留 `parser / blocks / hook_out / saw_osc133 / exec /
  completion_seq`，新增 `exec_lock`（同锚点串行化）；`messages / busy / generation /
  cancel / approval` 移到 `Conversation`。
- `TabRoute.ai` 改为 `context`；`AppCore` 增加 `conversations`；`ai_handle` 拆成
  `conversation_handle(id)` 与 `anchor_for(tab_id)`。
- `UiRuntime` 同时持有 conversation 与 anchor；`request_approval` 写会话、`run_with_sentinel`
  写锚点上下文。
- `answer_card` / `ai-send` / `ai-cancel` 的 `tab_id` 参数改为 `conversation_id`。
- 保留「一个 tab 一个会话」的临时映射：首次需要时按当前 tab 惰性建会话，行为与现在一致。

**出口**：现有 `tests/app/ai_copilot` 全绿（改成面向 `TabContext` + `Conversation`），
单 tab 场景手工回归无差异；应用行为零变化。

### WP2 持久化与恢复

- 持久化 DTO `StoredMessage`（`serde`）与 `AiMessage` 双向转换；**不要给 Slint 生成类型加
  derive**（见需求文档 §4）。`approval / cancel / generation` 是运行时对象，不落盘。
- `ai_conversations.json`：`data_dir()` 下、tmp+rename 原子写、unix 0600、损坏时保留原文件并
  回退为空 store（记 error log，不静默清空）。
- 写盘策略：每轮结束防抖 500ms 批量写 + 退出 flush；不逐 token 写盘。
- 恢复规则：`running` → `interrupted`；`pending` 卡片 → `expired`；落盘前消息过现有 `redact`。
- `sessions.json` 新增可选字段：`ai_max_parallel`（默认 3）、`ai_panel_width`（360|520）。
- 单会话上限 500 条 / 4MB，淘汰最旧的非卡片消息（卡片保留）。
- 测试：`tests/app/ai_conversations/mod.rs`（round-trip、上限、卡片过期、权限、损坏回退）。

**出口**：`cargo test` 通过；构造 store 写盘→重载，会话/状态/卡片与写入前一致。

### WP3 全局面板（单会话先跑通）

- 在 `ui/app.slint` 的 `quick-area → central` 层实现右侧 dock：`central` 宽度扣减面板宽度，
  `AiPanel` 绝对定位在右侧；终端宽度变化继续走现有 `content-resized`，不加第二套布局。
  `TerminalView` 不再渲染 `AiPanel`。
- 窗口属性：`ai-open`（窗口级开关）、`ai-conversations`（列表模型）、`ai-active-id`、`ai-messages`、`ai-busy`、
  `ai-title`、`ai-anchor-name`；`TerminalView` 只保留 `ai-completion`。
- 头部：星标 + 标题（点击展开列表）+ 模型 chip + 模式 chip + 齿轮 + 关闭；宽度两档
  360/520，默认 360，切换写 `ai_panel_width`。
- 快捷键上移：`Ctrl+Space` 在窗口层处理（终端聚焦时也生效）；`Ctrl+Shift+O`
  （macOS `⌘⇧O`）新建会话，注册在窗口层并在终端 view 之前拦截；补快捷键帮助表。
- 面板展开时终端区 `content-resized` 收缩，不覆盖终端。

**出口**：F1 验收 1/3/4；单会话收发、卡片、停止与现在一致。

### WP4 会话管理

- 新建（锚定当前 tab / 无锚点）、切换、关闭（运行中二次确认并取消）、列表 popover
  （标题、锚点名、状态点、更新时间）。
- 并发闸门：`running_count >= ai_max_parallel` 时发送按钮禁用并提示，不排队。
- 标题取首条用户消息前 30 字；重命名留到 M2。
- 切换会话：从 store 重放消息、< 100ms；运行中会话切回滚底并显示 Stop。

**出口**：F4 验收 1/4；连续切换 20 次无消息串线。

### WP5 后台运行与进度

- delta sink 只写 store；可见性判断 + 50ms 合并后刷 Slint。
- 关闭面板 / 切 tab / 切会话都不触碰 `generation`；Stop 才递增并取消本轮。
- 会话列表状态点（running 脉冲）、会话内运行指示复用现有样式。
- 窗口关闭不清会话；应用退出时取消所有运行中轮次并 flush 落盘。

**出口**：F4 验收 2、F5 验收 1/2；后台 3 会话跑 5 分钟，前台切换无明显卡顿。

### WP6 锚点解析与执行串行化

- `Anchor` 解析链：`anchor_tab → TabRoute → SessionHandle.commands + session + jump`；
  tab 已关闭或无 PTY 时 `anchor_lost = true`，本轮以无终端上下文运行并在 UI 提示。
- 同锚点执行锁：`TabContext.exec_lock` 用 `AtomicBool` 或 `Mutex<()>`，只覆盖
  `run_with_sentinel` 的 arm → 结果返回；超时/取消必须释放。
- 持锁失败：`execute_approved` / `execute_internal` 返回可识别的 `anchor_busy` 错误，
  引擎按工具失败继续；卡片 disposition 置 `filled`，UI 明示「另一会话正在该终端执行」。
- 审批仍是 180s 超时、`oneshot` 进程内通道；删除会话 / 停止先结算 pending 为拒绝。

**出口**：F4 验收 3；两个会话同锚点并发执行，第二个不向 PTY 写任何字节。

### WP7 启动接线与下线旧抽屉

- 删除 `TerminalState.ai-open / ai-busy / ai-messages` 与 `terminal_view.slint` 的
  overlay、`resync_conversation(tab)` 旧路径；保留命令补全（`ai-completion`）。
- 启动加载 `ai_conversations.json`：会话按 `anchor_tab` 懒解析；`running → interrupted`；
  pending 卡片置灰 `expired`。
- 退出 flush：窗口关闭不落盘等待，应用退出时同步写一次（失败只记日志，不阻塞退出）。
- 更新 `docs/AI_COPILOT.md`（面板行为、快捷键、数据文件）、`CHANGELOG.md`、快捷键帮助表。

**出口**：F1 验收 2；重启后列表完整、interrupted 可继续提问、无 pending 可点；无旧 UI 残留。

### WP8 验证与收尾

- 单测：store round-trip、上限、恢复规则、并发计数、执行锁、宽度持久化、脱敏落盘。
- 手工矩阵：Windows / macOS / Linux；中文 IME；htop/btop 全屏；分屏；多窗口拖 tab；
  睡眠唤醒；3 会话并行 5 分钟。
- 性能：10 个会话常驻内存增量 < 20MB；切会话 < 100ms；后台流式不导致前台掉帧。
- CI：`cargo fmt --check`、`cargo clippy --workspace --all-targets -- -D warnings`、
  `cargo test`、release build 全绿。

---

## 3. PR 切片与顺序

| # | 分支内容 | 依赖 | 说明 |
|---|---|---|---|
| 1 | `refactor(ai): split conversation state from terminal context` | — | WP1，纯重构，行为不变；现有测试改造后必须全绿 |
| 2 | `feat(ai): persist conversations and restore interrupted state` | #1 | WP2，纯逻辑 + 单测，不接 UI |
| 3 | `feat(ai): move copilot panel to a global dock` | #1 #2 | WP3，先单会话跑通；内部可临时保留旧入口，合入前删除 |
| 4 | `feat(ai): multi-conversation create switch and list` | #3 | WP4 |
| 5 | `feat(ai): background runs concurrency and anchor exec lock` | #4 | WP5 + WP6 |
| 6 | `feat(ai): wire startup restore and retire the legacy drawer` | #5 | WP7 + WP8 收尾 |

每个 PR 保持 `main` 可构建、CI 全绿；#3 是最大的一次性改动，建议单独评审。

---

## 4. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| 一次性搬 UI 导致终端布局回归 | 高 | #3 内部保留旧 overlay 作对照，合入前删除；先跑 `tests/app/terminal_*` 与分屏/全屏手工用例 |
| 后台会话每 token 刷 Slint | 卡顿/内存 | D9：可见性过滤 + 50ms 合并；压测 3 个后台会话 |
| `TabContext` 跨 await 持锁 | 死锁 | 沿用现有「短临界区 + clone handle」模式；执行锁单独一把，不与消息锁嵌套 |
| 锚点 tab 在轮次中被关闭 | 执行悬挂 | 关闭 tab 时把锚点标记 lost，并 `clear_exec` + 取消该锚点的执行等待；最坏由现有超时兜底，测试覆盖 |
| 多窗口拖 tab 后会话指向旧窗口 | 消息不刷新 | 解析锚点时实时读 `tab_routes`，不缓存 `Weak<AppWindow>`；刷新按当前窗口的 `ai-active-id` 命中 |
| 落盘内容含敏感信息 | 安全 | 复用 `redact` 后再序列化；0600 + 原子写；测试构造内网 IP / `sk-` 用例 |
| 并发上限与「同锚点串行」叠加后体验变差 | 用户困惑 | UI 分别提示「并发已满」与「该终端正被另一会话使用」，文案区分 |

---

## 5. Definition of Done

- [ ] 3 个会话并行运行，切换 < 100ms，切回 2s 内看到最新流式输出与计划状态。
- [ ] 关闭面板 5 分钟后重开，运行中会话消息无丢失、无重复。
- [ ] 同锚点两个会话并发执行命令，第二个不写 PTY 且有明确提示。
- [ ] 第 4 个会话发送被禁用并提示并发已满。
- [ ] 重启后会话恢复为 `interrupted`，pending 卡片全部 `expired`，可继续提问。
- [ ] 面板宽度档位重启保持；`Ctrl+Space` / `Ctrl+Shift+O` 不向 PTY 泄漏字符。
- [ ] 旧 per-tab 抽屉 UI 与代码路径删除，无数据迁移逻辑。
- [ ] `fmt` / `clippy -D warnings` / `test` / release build 全绿。

---

## 6. 开工顺序建议

1. 先做 **WP1（拆分）**：它是所有后续工作的地基，且能在不改变行为的前提下用现有测试
   验证；先做持久化会因 `TabAi` 结构未拆而反复改 store 接口。
2. 再做 **WP2（持久化与恢复）**：纯逻辑，单测覆盖，不阻塞 UI。
3. 然后 **WP3 → WP4 → WP5/WP6 → WP7**。

> 本文的 D7/D8/D9 属于实施级决策，已按上述方案拍板；若评审有不同意见，只需调整
> `ConversationStore` 的归属（D7）与刷新策略（D9），不影响需求文档的验收标准。

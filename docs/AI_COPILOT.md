# AI Copilot（FengheShell × rssh 缝合方案）

两个项目互补：FengheShell 提供「全功能低开销的传统运维底座」（资源监控、多标签终端、
SFTP），rssh 提供「AI 运维 Copilot 范式」（无感上下文捕获、AI Triage、本地脱敏、
带副作用评级的命令执行）。两边都是 Rust，因此不需要跨语言 FFI 胶水层 —— AI 侧的
逻辑以独立 crate 的形式注入基座。

> **多会话面板（GitHub Copilot 风格布局：模型/模式/会话切换、记忆/技能/MCP 配置、
> 多会话并行与历史管理）的需求分析与功能规划见 [AI_PANEL_REQUIREMENTS.md](AI_PANEL_REQUIREMENTS.md)。**

```text
┌──────────────────────────────────────────────────────────┐
│                      Slint 视图层（ui-slint）            │
│  ┌────────────────┐ ┌─────────────────┐ ┌──────────────┐ │
│  │ 资源监控侧边栏 │ │  PTY 终端视窗   │ │ AI 协同抽屉  │ │
│  │ (FengheShell)    │ │ 命令块 / ANSI   │ │ ai_panel     │ │
│  └────────────────┘ └─────────────────┘ └──────────────┘ │
├──────────────────────────────────────────────────────────┤
│                    Rust 核心（crates/ai-copilot）         │
│  blocks       OSC 133 语义块 + 8KB 上下文窗口             │
│  redact       编号占位符脱敏 + 本地反向还原映射           │
│  sanitize     tree-sitter 命令形状校验 + 黑名单           │
│  risk         三档风险分级 + Run Gate 裁决                │
│  triage       LLM 编排 / 工具循环 / HITL 审批             │
│  shell         POSIX / PowerShell / cmd 适配             │
├──────────────────────────────────────────────────────────┤
│                 FengheShell 宿主（src/app/ai.rs）           │
│  TabAi        每标签的上下文 + 抽屉状态                   │
│  UiRuntime    ToolRuntime 实现：写 PTY / 读远端文件       │
└──────────────────────────────────────────────────────────┘
```

## 怎么用

1. 终端状态条右侧点 `AI` 打开抽屉，或按 **Ctrl+Space** 开关当前标签的抽屉。
2. 配置 LLM：设置 → Interface → **AI Copilot** 页（或抽屉标题栏的齿轮）：协议 /
   端点 / 模型 / API Key，以及「本地脱敏」与「只读命令免确认执行」两个开关。设置写进
   `sessions.json` 的 `ai_*` 字段，API Key 与其它会话密码一样用 ChaCha20-Poly1305
   加密落盘；输入框里的密钥是只写的，保存后即清空，已保存的密钥不会被读回界面。
3. 直接提问，或什么都不问 —— CPU / 内存 / 磁盘越界时打开抽屉会自动起一轮排查。
4. AI 给出的命令会以卡片形式出现在对话里，按风险等级决定你能怎么操作（见下）。

## 工作方式：Ask / Agent（参考 GitHub Copilot 的能力分层）

GitHub Copilot 有三层能力：补全 → 对话/编辑 → 代理。在运维场景里对应成两层：

| Copilot 层 | FengheShell 对应 | 行为 |
| --- | --- | --- |
| Chat / Edit | **Ask**（默认） | 解释现象、定位原因、给出命令建议；工具回合上限 2，不主动落地改动 |
| Agent | **Agent** | 自己规划 → 取证 → 执行 → 验证 → 汇报；工具回合上限 6，每一步在抽屉里留痕 |

两种模式共用同一套工具与 Run Gate：Agent 并不会绕过审批，橙/红命令仍然只填入终端。
区别只是**回合预算**和**系统提示**（Agent 会额外收到「先取证、再动手、最后验证」的工作方式）。

抽屉里的星形步骤行就是 Agent 的工具调用记录：取证跑过什么、哪一步失败了，用户不必只信结论。

入口：终端状态条右侧的**五芒星**（打开时填充强调色），或 **Ctrl+Space**。空会话时会给出三个
起手建议（都是先只读的排障问法）。设置里的 **Test connection** 会用当前填写的配置请求一次
`/models` 做连通性自检，不写盘。

### 计划清单（Agent）

Agent 模式会先用 `set_plan` 工具把计划发布成一份**清单**（最多 8 条），抽屉里渲染成
带复选框的步骤行，状态随执行推进：

| 状态 | 图标 | 含义 |
| --- | --- | --- |
| `pending` | 空心框 | 还没轮到 |
| `running` | 星标（强调色） | 正在执行 |
| `done` | 勾选框（绿） | 对应的一次工具调用成功 |
| `failed` | 破折框（红） | 对应的一次工具调用失败或被拦下 |

推进规则是「第 n 次动作型工具调用对应第 n 步」——这是有意做的简化：让模型逐步回报进度
既啰嗦又不可靠。清单只用于**展示进度**，真正的执行结果仍以命令卡片和步骤痕迹为准。

### 补全层（命令输入框的幽灵文本）

对应 Copilot 第一层：在命令栏输入框里，敲到一半时模型把后续命令以灰色幽灵文本画在光标后面，Tab 接受，Esc 只清建议不丢焦点。

- 输入停顿 400ms 才发请求，少于 3 个字符不发；没有配置 API Key 时整层不启用
- 请求带最近执行过的 4 条命令作为上下文，但不带工具：补全阶段永远不可能执行任何东西（runtime 是恒拒绝的实现）
- max_tokens 只有 64，一次补全几十个 token；10 秒超时即静默放弃
- 每次输入变化都会作废上一次响应（序号守卫），旧建议不会盖到新输入上

## 上下文是怎么抓的


传统终端只是一串无状态的字符流，AI 要能诊断，前提是分清「哪一段是命令、哪一段是输出」。
`crates/ai-copilot/src/blocks.rs` 在会话 pump 线程上对输出流做两件事：

- **OSC 133 语义块**（iTerm2 / VSCode / Kitty 同一套协议）：遇到 `ESC ] 133 ; A/B/C/D`
  就切出「命令 + 输出 + 退出码」。远端 shell 装了 shell integration 时优先走这条路。
- **FengheShell shell hook 兜底**：FengheShell 连上后会在远端 shell 里装钩子，每条命令
  跑完在 precmd 阶段回报 `OSC 697`（事件 `SessionEvent::CommandRan`），据此切块。
  此时退出码未知，AI 看到的是 `[exit ?]`。

两条路都在数据离开本机之前先 `strip_ansi` 清洗 CSI / OSC 等转义序列，并按照 8 KB
滑动窗口截断（`tail -f` 这种滚屏不会产生 token 爆炸）。

## 脱敏与还原

`redact` 在转发之前把内置 8 条规则命中的内容替换成编号占位符
（`<INTERNAL_IP_1>`），映射表只存在本地内存。规则集与上游 rssh 的 seed 一致：
内网 IP（`10.x` / `172.16-31.x` / `192.168.x`）、`Bearer` 头、`sk-` 开头密钥、
`AKIA` 开头 AWS key、JWT（`eyJ…`）、32 位及以上的长 hex 串（哈希 / 会话号）。
**不覆盖** IPv6、内网域名、私钥块与 `export` 敏感字段 —— 那些内容会原样出网，
涉及它们的问题请自行规避或先改成本机占位符再提问。

AI 若把占位符写回命令 —— 例如 `curl -s http://<INTERNAL_IP_1>/api/health` ——
宿主在执行前会用同一张映射表反向还原成真实命令。注意顺序：**先还原、再过 shape
validator**，否则占位符里的尖括号会被当成 shell 重定向节点，把一条无害的探测命令误杀。

## 风险分级与 Run Gate

AI 提议的每条命令都要过四道墙，任何一道失败都不会碰到你的机器：

| 墙 | 作用 |
| --- | --- |
| 1. shape validator | tree-sitter 解析后按黑名单 + 每命令规则硬拦（`rm` / `bash -c` / `chmod -R` / 写重定向 / 无界循环 …） |
| 2. 风险分级 | `ReadOnly` 绿 / `Mutating` 橙 / `Destructive` 红 |
| 3. Human-in-the-loop | 绿灯（且开启免确认）自动放行；其余一律等你点按钮 |
| 4. 可见执行 | 命令写进**用户看得见的那个 PTY**，靠注入的 sentinel 回声取退出码与输出 |

UI 上的对应关系：

- **绿灯 + Run**：直接写入终端并回车（仍然发生在你眼前，没有后台静默执行）。
- **橙 / 红灯 + 填入终端**：只把命令写进终端的输入行，回车由你按。
- **红色 + blocked_reason**：shape validator 已经拒绝，按钮都不给你 —— AI 只会收到
  拒绝原因并调整策略。

审批有 180 秒上限，超时或抽屉关闭都按「拒绝」结算，AI 不会卡死。

`run_command` 可以带 `timeout_s`（1..=300 秒）：LLM 声明的等待上限会透传给宿主，
没声明则用宿主默认（30 秒）。file_ops 的后端模板命令不走 LLM 超时。

## YOLO 模式（完全信任）

设置 → Interface → AI Copilot 页的 **YOLO 模式（完全信任）** 开关（默认关，
即时生效、跨窗口同步）打开后，上面所有的护栏一次性全部撤掉：

- **脱敏关闭**：系统提示、终端上下文、命令输出、网页正文都不再过脱敏规则 ——
  终端里出现的密钥、Token 会原样发往你所配置的模型服务商。
- **shape validator 跳过**：`rm -rf`、无界循环、写重定向等形态照单全收。
- **审批全免**：只读 / 有副作用 / 高危命令一律直接执行，`run_command`、
  file_ops 的四个步骤、`web_fetch` 都不再弹卡；「只读命令免确认执行」被覆盖。
- **审计留痕**：每轮开始时会记一条 `yolo mode active` 的 Note，执行记录照常，
  导出后能看到这个模式期间发生的一切。

开启期间抽屉顶部常驻一条红色警示横幅。适用场景：受控环境（容器 / 快照可随时
回滚的虚拟机）、完全本地的模型（如 Ollama）、或你就是要 AI 全自动干活的演练。
任何面向生产凭据或不可逆操作的场景都不要开。关闭后所有护栏立即恢复。

## 审计日志

每轮诊断都会在引擎里记一份审计（rssh 同款事件点移植）：会话开始 / 用户提问 /
每次 LLM 请求与回包的 token 数 / 命令的提议、审批、拦截与执行（含脱敏后的输出、
字节数与耗时）/ Skill 加载 / web_search 与 web_fetch 的完成情况 / 备注与错误。

- 只在**进程内存**里累积，不自动落盘；退出即清空。
- 实时写入：用户中途「停止」的轮次，已发生的事件同样留在日志里。
- 输出内容按当轮的「本地脱敏」开关处理，但仍含命令与输出 —— 导出文件按敏感文件保管。
- 设置 → Interface → **AI Copilot** 页的 **Export audit log** 可保存为文本
  （`fengheshell-ai-audit.log`），grep / less 友好。

## 硬件快照融合

Triage 的 system prompt 里带着监控侧边栏同源的本机快照：CPU、内存 / 交换、负载、
每个挂载点的用量、网络收发速率。所以 AI 不只是读到你的终端，还读到主机状态 ——
CPU 飙到 90% 或某个挂载点剩余不足 10% 时，打开抽屉就会自动以
`[AUTOMATIC TRIAGE]` 的方式起一轮排查，不用自己组织问题。

## MCP 反向调用

FengheShell 自带 MCP Server（对外给别的客户端用）。AI Copilot 则是同一 automation 层的
另一个客户端：`read_remote_file` 工具直接复用 `automation::read_text`，通过已保存的
会话（含跳板链）读远端文件，因此你可以在抽屉里问「看看 /var/log/nginx/error.log 最后
50 行错误」而不用自己去 SFTP 面板翻。

## Web 工具（web_search / web_fetch）

排障到一半需要查公开资料时，AI 可以直接用两个 web 工具（rssh 同款移植）：

- **web_search**：走 Exa / Parallel 的匿名 Hosted MCP。查询**发出前**先在本地过
  脱敏规则（内网 IP / Token / 密钥换成 `<REDACTED:…>`）—— 这是网络出站边界，
  不靠模型自律；提供方按「模型@端点」的哈希二选一（负载均衡），可用环境变量
  `FENGHESHELL_WEB_SEARCH_PROVIDER=exa|parallel` 固定。MCP 的文本响应原样喂给
  LLM，不做结构化解析。
- **web_fetch**：抓一个具体 URL 并转成 Markdown（HTML 全页转换，DOM 层丢弃
  script/style 等，script 文本永远不会变成 Markdown）。5 MiB 响应上限、
  64 KiB Markdown 截断；每次抓取都会弹出审批卡片，URL 对用户可见。

两个工具返回的内容都是**不可信外部数据**：引擎会在结果前加警告，提示注入面
（「忽略之前指令」之类的页面文本）由这层警告 + 模型指令共同防。

## 文件修改（match_file / patch_file）

排障经常要改配置（超时、开关、prometheus job…）。FengheShell **禁止一切自由形式
的写文件命令**（`>` / `>>` / `tee` / `cp` / `mv` / `sed -i` / `python` … 都会被
shape validator 拦下），唯一通路是 rssh 同款的两步工具（Agent 模式可用）：

| 工具 | 作用 | 审批 |
| --- | --- | --- |
| `match_file(path, find)` | 在远端文件里定位字面文本，回 `{count, matches:[{line, context}]}`（远端 cap 50 条） | 只读：开了「只读命令免确认执行」时自动放行，否则一张卡 |
| `patch_file(path, find, replace, expected_count)` | 把 `find` 全部替换为 `replace`，原子写回（tmp + mv），回 unified diff | 四张卡：cp → modify → diff → mv，每步都要点 |

安全设计与 rssh 一致：

- 命令由**后端模板**拼装（远端 `python3 -c $'…'`，perl 降级），不过 shape
  validator；LLM 可控的只有 `find` / `replace` 文本，且全部经 ANSI-C 引号编码
  （控制字符 hex 化，防终端转义注入；长多行脚本也因此保持单行，绕开 zsh ZLE 的
  multi-line quote race）。
- `patch_file` 落盘前重新读取文件并**校验出现次数**，与 `expected_count` 不符就
  拒绝（race / 陈旧防护）；替换内容与原内容相同时跳过 `mv`，不碰 mtime/inode。
- diff 为 0（无差异）时不覆盖文件，tmp 留给用户自己处置。
- 远端需要 `python3`（首选）或 `perl`；`patch_file` 另需 `diff`。连上后第一次使用
  时会在终端里跑一行只读探测（`echo "py3=… perl=… diff=…"`，不弹卡片），结果按轮次
  缓存。仅 POSIX shell（bash/zsh）支持 —— Windows / 串口 / Telnet 会话会得到明确错误。

## 技能（load_skill）

`general` 规则集（诊断方法论 + Java/Go 剧本）永远展开在 system prompt 里。用户还
可以把**自己的排查流程**写成 Skill，按需加载：

在 `sessions.json` 里加 `ai_skills` 数组（没有管理 UI，直接编辑配置文件；`id` 不能
是 `general`）：

```json
"ai_skills": [
  {
    "id": "user-mysql",
    "name": "MySQL 慢查询排查",
    "description": "慢查询 / 锁等待 / 主从延迟的标准流程",
    "content": "1. show full processlist; 2. …"
  }
]
```

配置了之后，system prompt 会带上「Available skills」目录（id + 一句话描述），模型
判断匹配就调 `load_skill(id)` 拉全文。会话启动时快照进引擎，中途改配置文件不影响
正在跑的轮次。

## LLM 支持矩阵

| protocol 值 | 端点示例 | 说明 |
| --- | --- | --- |
| `openai-completions` | `https://api.openai.com/v1` | OpenAI 及任意 OpenAI 兼容服务（DeepSeek / Groq / Moonshot …） |
| `deepseek-thinking` | `https://api.deepseek.com` | 带 reasoning_content 回传 |
| `anthropic-messages` | `https://api.anthropic.com` | Claude Messages API |
| `ollama` | `http://localhost:11434/v1` | 本地模型，数据完全不出本机 |

## 已知限制

- 本地终端标签没有安装 hooks（`OSC 697` 是连远端 SSH 时装进去的），这类标签的命令块
  只能来自远端自身启用的 OSC 133，否则 AI 只看到你的提问文本。
- 「停止」会置位本轮的中断开关：引擎在下一个回合边界退出，客户端在下一个流式分块处
  放弃请求，命令等待也会立刻结束。已经生成的那一小段文本会被丢弃（generation 机制）。
- 串口 / Telnet 这类裸设备没有 shell，sentinel 无处附着，因此命令执行不适用，AI 只会
  给文本建议。
- match_file / patch_file 只支持 POSIX shell（bash/zsh）的远端，且需要 python3 或 perl
  （patch_file 另需 diff）；Windows / 串口 / Telnet 会话会拿到明确错误，应改用
  run_command 的 grep / head 只读查看。
- 用户自定义 Skill 目前只能手改 `sessions.json` 的 `ai_skills` 字段，没有管理界面。
- web_search 的查询脱敏目前只走内置 8 条规则（内网 IP / Token / 密钥），用户自定义
  脱敏规则暂不参与；需要时可以经引擎透传。
- 审计日志只在进程内存里累积，不自动落盘；退出即清空，需要留痕请用设置页的导出按钮。

---

# AI Copilot (FengheShell × rssh)

English summary of the sections above.

## What it is

FengheShell supplies the "full-featured, low-overhead classic ops workbench"
(resource monitoring, multi-tab terminal, SFTP). rssh supplies the "AI ops Copilot
paradigm" (invisible terminal context capture, AI triage, local redaction,
side-effect-rated command execution). Both are Rust, so there is no FFI glue —
the AI side is injected as an independent crate.

## Usage

1. Click `AI` on the terminal status strip, or press **Ctrl+Space** to toggle the
   drawer of the active tab.
2. Configure the LLM under Settings -> Interface -> **AI Copilot** (or the gear in
   the drawer header): protocol /
   endpoint / model / API key, plus "Redact secrets locally" and
   "Auto-run read-only commands". Settings are stored in `sessions.json`
   under the `ai_*` fields; the API key is encrypted with ChaCha20-Poly1305
   like every other stored secret.
3. Ask a question, or ask nothing at all — when CPU / memory / disk cross the
   alert thresholds, opening the drawer starts a triage round automatically.
4. Suggested commands arrive as cards; the risk tier decides what you can do
   with them (see below).

## Working modes: Ask / Agent (mirroring GitHub Copilot's layers)

GitHub Copilot stacks three capabilities - completion, chat/edit, agent. Mapped
onto an ops terminal they become two explicit modes:

| Copilot layer | FengheShell mode | Behaviour |
| --- | --- | --- |
| Chat / Edit | **Ask** (default) | Explain, locate the cause, suggest commands; 2 tool turns, never acts on its own |
| Agent | **Agent** | Plan -> gather evidence -> act -> verify -> report; 6 tool turns, every step leaves a trace |

Both modes share the same tools and Run Gate - Agent never bypasses approval,
amber/red commands are still only filled into the terminal. The difference is the
**turn budget** and the **system prompt** (Agent additionally gets the
"gather first, act second, verify last" working style).

The starred step rows in the drawer are the Agent's tool calls: what it probed and
which step failed, so the user does not have to trust the conclusion alone.

Entry point: the **five-pointed star** on the right of the terminal status strip
(filled with the accent colour while open), or **Ctrl+Space**. An empty session
offers three starter prompts, all read-only first. **Test connection** in the
settings block issues a single `/models` request with the typed values - it writes
nothing to disk.

### Plan checklist (Agent)

In Agent mode the model first publishes a plan through the `set_plan` tool (up to 8
steps). The drawer renders it as a checklist whose state advances as it works:

| State | Icon | Meaning |
| --- | --- | --- |
| `pending` | empty box | not reached yet |
| `running` | star (accent) | executing now |
| `done` | checked box (green) | its tool call succeeded |
| `failed` | dash box (red) | its tool call failed or was refused |

Progress follows "the n-th action tool call completes step n" - a deliberate
simplification, since asking the model to report progress per step is verbose and
unreliable. The checklist shows progress only; the authoritative result is still the
command cards and the step log.

### Completion layer (ghost text in the command box)

Mirrors Copilot's first layer: while you type in the command bar, the model draws what
should come next as grey ghost text after the caret. Tab accepts it, Esc dismisses the
suggestion without losing focus.

- Requests are debounced by 400 ms and skipped below 3 characters; with no API key
  configured the layer stays off entirely
- The last 4 executed commands ride along as context, but the request carries no tools:
  completion can never execute anything (its runtime refuses every call)
- max_tokens is 64, so a completion costs tens of tokens; it gives up silently after a
  10 s timeout
- Every keystroke invalidates the previous response (sequence guard), so a stale
  suggestion can never be painted over new input

## Context capture


The terminal is an unlabelled character stream. Before AI can diagnose anything,
it has to know which part was the command and which part was its output.
`crates/ai-copilot/src/blocks.rs` runs two strategies over the stream on the
session pump thread:

- **OSC 133 semantic blocks** (the iTerm2 / VSCode / Kitty protocol):
  `ESC ] 133 ; A/B/C/D` boundaries cut "command + output + exit code".
- **FengheShell shell hook fallback**: FengheShell installs a hook in the remote
  shell after login; every command reports `OSC 697` at precmd (event
  `SessionEvent::CommandRan`), which we use to cut blocks. The exit code is
  unknown in this mode, so the AI sees `[exit ?]`.

Both paths `strip_ansi`-clean CSI / OSC noise and cap the window at the last
8 KB, so `tail -f` cannot blow up the token budget.

## Redaction and restoration

Before anything leaves the machine, `redact` replaces what the built-in eight
rules match with numbered placeholders (`<INTERNAL_IP_1>`). The rule set is the
same as upstream rssh's seed: private IPs (`10.x` / `172.16-31.x` / `192.168.x`),
`Bearer` headers, `sk-` keys, `AKIA` AWS keys, JWTs (`eyJ…`) and long hex
strings (32+ chars - hashes / session ids). **Not covered**: IPv6, internal
hostnames, private-key blocks and sensitive `export` fields — those leave the
machine verbatim, so avoid them in questions or pre-replace them yourself.

## Run gate

Every proposed command crosses four walls, and failing any of them means it
never touches your box:

| Wall | Effect |
| --- | --- |
| 1. shape validator | hard block by blacklist + per-command rules (`rm`, `bash -c`, `chmod -R`, write redirects, unbounded loops, …) |
| 2. risk tier | `ReadOnly` green / `Mutating` amber / `Destructive` red |
| 3. human in the loop | green passes automatically when auto-run is enabled; everything else waits for your click |
| 4. visible execution | the command goes to the **PTY you are looking at**, and the exit code comes back through an injected sentinel echo |

Red: `systemctl stop`, `git reset --hard`, `useradd`, `chmod 777` …
Amber: `systemctl restart`, `apt install`, `docker image prune` …
Green: `cat`, `df -h`, `ps aux --sort=-%cpu | head`, `journalctl -u nginx` …

Approval requests time out after 180 s; a timeout or a closed drawer counts as a
rejection, so the AI never wedges.

`run_command` may carry `timeout_s` (1..=300 s): the LLM's requested wait is
forwarded to the host; without it the host default (30 s) applies. file_ops
backend-template commands never take an LLM timeout.

## YOLO mode (full trust)

The **YOLO mode (full trust)** switch on the Settings -> Interface -> AI Copilot
page (off by default, applied instantly and synced across windows) removes every
guard rail described above at once:

- **Redaction off**: system prompt, terminal context, command output and fetched
  pages no longer pass through the redaction rules - secrets and tokens visible
  in your terminal are sent verbatim to whichever model provider you configured.
- **Shape validator skipped**: `rm -rf`, unbounded loops, write redirects and the
  rest are accepted as they come.
- **No approvals at all**: read-only, mutating and destructive commands all run
  directly; `run_command`, the four file_ops steps and `web_fetch` stop showing
  cards, and "auto-run read-only" is superseded.
- **Audit trail kept**: each round starts with a `yolo mode active` note, and
  executions are recorded as usual, so an export shows everything that happened
  while the mode was on.

A red warning banner stays pinned to the top of the drawer while the mode is on.
Good uses: controlled environments (containers, VMs you can snapshot), fully
local models (e.g. Ollama), or rehearsals where you want the AI to work
unsupervised. Do not enable it around production credentials or irreversible
operations. Turning it off restores every guard rail immediately.

## Audit log

Every diagnosis round records an audit inside the engine (same event points as
rssh): session start / user question / each LLM request with its token counts /
command proposed, rejected, blocked and executed (with redacted output, byte
counts and duration) / skill loads / web_search and web_fetch completions /
notes and errors.

- It accumulates in **process memory** only and is never written automatically;
  exiting the app clears it.
- Entries are written as they happen, so a round the user stops mid-way still
  keeps everything that already occurred.
- Output honours the round's "Redact secrets locally" switch, but still contains
  commands and output - treat an export as a sensitive file.
- **Export audit log** on the Settings -> Interface -> **AI Copilot** page saves
  it as text (`fengheshell-ai-audit.log`), grep / less friendly.

## Web tools (web_search / web_fetch)

When a diagnosis needs public references, the model can reach two web tools (ported
from rssh):

- **web_search** goes through the anonymous Hosted MCP of Exa / Parallel. The query
  is redacted locally (private IPs / tokens / keys become `<REDACTED:…>`) **before**
  it leaves the device — that is the network egress boundary, not model discipline.
  The provider is picked by hashing "model@endpoint" (load balancing) and can be
  pinned with `FENGHESHELL_WEB_SEARCH_PROVIDER=exa|parallel`. The MCP text response
  is fed to the LLM verbatim, without structured parsing.
- **web_fetch** fetches one exact URL and converts it to Markdown (full-page
  conversion; script/style are dropped at DOM level, so script text never becomes
  Markdown). 5 MiB response cap, 64 KiB Markdown truncation, and every fetch shows
  the user an approval card with the URL visible.

Both tools return **untrusted external data**: the engine prefixes the result with a
warning, and that warning plus the system prompt together cover the prompt-injection
surface (page text saying "ignore previous instructions").

## File modification (match_file / patch_file)

Diagnosis often ends in a config change (a timeout, a flag, a prometheus job…).
FengheShell **forbids every free-form file write** (`>` / `>>` / `tee` / `cp` / `mv` /
`sed -i` / `python` … are all rejected by the shape validator); the only path is the
two-tool workflow ported from rssh (Agent mode):

| Tool | Effect | Approval |
| --- | --- | --- |
| `match_file(path, find)` | Locates literal text in a remote file, returns `{count, matches:[{line, context}]}` (remote cap 50) | read-only: auto-approved when "auto-run read-only" is on, otherwise one card |
| `patch_file(path, find, replace, expected_count)` | Replaces every `find` with `replace`, writes back atomically (tmp + mv), returns the unified diff | four cards: cp → modify → diff → mv, each needs a click |

Safety mirrors rssh:

- The commands are assembled from **backend templates** (remote `python3 -c $'…'`,
  perl as fallback) and skip the shape validator; the LLM only controls `find` /
  `replace`, which go through ANSI-C quoting (control characters hex-encoded against
  terminal escape injection; long multi-line scripts stay single-line, avoiding the
  zsh ZLE multi-line quote race).
- `patch_file` re-reads the file before writing and **verifies the occurrence count**
  against `expected_count` (race / staleness guard); a replacement identical to the
  original skips the `mv` so mtime/inode stay untouched.
- diff exit 0 (no difference) leaves the file alone and the tmp for the user.
- The remote needs `python3` (preferred) or `perl`; `patch_file` additionally needs
  `diff`. The first use runs one read-only probe in the terminal
  (`echo "py3=… perl=… diff=…"`, no card), cached per round. POSIX shells (bash/zsh)
  only — Windows / serial / Telnet sessions get a clear error.

## Skills (load_skill)

The `general` rule set (methodology + Java/Go playbooks) is always expanded into the
system prompt. Users can additionally write **their own runbooks** as skills, loaded
on demand:

Add an `ai_skills` array to `sessions.json` (no management UI — edit the config file;
`id` must not be `general`):

```json
"ai_skills": [
  {
    "id": "user-mysql",
    "name": "MySQL slow-query triage",
    "description": "Standard flow for slow queries / lock waits / replica lag",
    "content": "1. show full processlist; 2. …"
  }
]
```

With skills configured, the system prompt carries an "Available skills" catalog
(id + one-line description) and the model calls `load_skill(id)` when one matches.
The catalog is snapshotted into the engine at round start; editing the file mid-round
does not affect a running round.

## Known limitations

- Local terminal tabs have no hook (`OSC 697` is installed into remote shells over
  SSH), so their context relies on the remote shell emitting OSC 133 — otherwise
  the AI only sees your question.
- "Stop" flips the round's cancel flag: the engine exits at the next turn boundary, the
  client gives up at the next streamed chunk, and any command wait ends immediately. The
  text already generated is dropped (generation counter).
- Raw-device sessions (serial / Telnet) have no shell to carry a sentinel, so command
  execution does not apply there; the AI answers in prose.
- match_file / patch_file support POSIX shells (bash/zsh) only and need python3 or perl
  on the remote (patch_file additionally `diff`); Windows / serial / Telnet sessions
  get a clear error and should fall back to read-only run_command (grep / head).
- User-defined skills can only be added by hand today: edit the `ai_skills` array in
  `sessions.json`; there is no management UI.
- web_search query redaction currently uses the built-in eight rules only (private
  IPs / tokens / keys); user-defined redaction rules do not participate yet.
- The audit log lives in process memory only and is never written automatically;
  it clears on exit - use the export button on the settings page to keep a copy.

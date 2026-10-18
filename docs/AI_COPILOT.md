# AI Copilot（FengheShell × rssh 缝合方案）

两个项目互补：FengheShell 提供「全功能低开销的传统运维底座」（资源监控、多标签终端、
SFTP），rssh 提供「AI 运维 Copilot 范式」（无感上下文捕获、AI Triage、本地脱敏、
带副作用评级的命令执行）。两边都是 Rust，因此不需要跨语言 FFI 胶水层 —— AI 侧的
逻辑以独立 crate 的形式注入基座。

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
2. 点标题栏齿轮配置 LLM：协议 / 端点 / 模型 / API Key，勾选「本地脱敏」与
   「只读命令免确认执行」。设置写进 `sessions.json` 的 `ai_*` 字段，API Key
   与其它会话密码一样用 ChaCha20-Poly1305 加密落盘。
3. 直接提问，或什么都不问 —— CPU / 内存 / 磁盘越界时打开抽屉会自动起一轮排查。
4. AI 给出的命令会以卡片形式出现在对话里，按风险等级决定你能怎么操作（见下）。

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

`redact` 在转发之前把内网 IP / IPv6 / 内网域名 / Bearer、JWT、AWS key、私钥块 /
`export` 里的敏感字段替换成编号占位符（`<INTERNAL_IP_1>`），映射表只存在本地内存。

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
2. In the drawer header, click the gear to configure the LLM: protocol /
   endpoint / model / API key, plus "Redact secrets locally" and
   "Auto-run read-only commands". Settings are stored in `sessions.json`
   under the `ai_*` fields; the API key is encrypted with ChaCha20-Poly1305
   like every other stored secret.
3. Ask a question, or ask nothing at all — when CPU / memory / disk cross the
   alert thresholds, opening the drawer starts a triage round automatically.
4. Suggested commands arrive as cards; the risk tier decides what you can do
   with them (see below).

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

Before anything leaves the machine, `redact` replaces private IPs / IPv6 /
internal hostnames / bearer & JWT tokens / AWS keys / private-key blocks and
sensitive `export` fields with numbered placeholders (`<INTERNAL_IP_1>`). The
mapping stays in local memory only. When the model echoes a placeholder back
inside a command, the host restores the real value before the command ever
reaches the shell. Order matters: **restore first, then validate** —
otherwise the angle brackets are parsed as shell redirections and an innocent
probe gets blocked.

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

## Known limitations

- Local terminal tabs have no hook (`OSC 697` is installed into remote shells over
  SSH), so their context relies on the remote shell emitting OSC 133 — otherwise
  the AI only sees your question.
- "Stop" flips the round's cancel flag: the engine exits at the next turn boundary, the
  client gives up at the next streamed chunk, and any command wait ends immediately. The
  text already generated is dropped (generation counter).
- Raw-device sessions (serial / Telnet) have no shell to carry a sentinel, so command
  execution does not apply there; the AI answers in prose.

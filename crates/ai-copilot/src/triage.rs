//! AI Triage 引擎：终端上下文 + 硬件快照 → LLM → 带风险分级的命令卡片。
//!
//! 这是缝合方案的「智能与安全」核心。一次 `ask()` 的生命周期：
//!
//! ```text
//! TriageContext { blocks(OSC133 上下文, 已截断), system(硬件快照?), question }
//!   → 本地脱敏（编号占位符 + RedactionMap）
//!   → system prompt（rssh/fengheshell 通用规则 + shell 家族 + 硬件快照段落）
//!   → LLM chat（带 run_command / read_remote_file 工具）
//!   → 每个 run_command 工具调用：
//!       1. sanitize::validate_with 硬校验（失败 → 工具错误回给 LLM）
//!       2. risk::assess_command 三档分级
//!       3. ToolRuntime::request_approval  ← Human-in-the-Loop 唯一执行入口
//!          （拒绝 → 工具错误回给 LLM；rssh 同款「拒绝后调整策略」）
//!       4. execute_approved 在用户可见的 PTY 执行，结果脱敏+截断回传
//!   → 循环直到 LLM 给出纯文本结论
//!   → 反向还原占位符（Final text + 命令卡片），返回 TriageOutcome
//! ```
//!
//! 引擎不直接持有任何 SSH/PTY 句柄 —— 所有副作用都经由 `ToolRuntime`
//! trait，由 FengheShell 以 `send_raw` / MCP automation 层实现（monkey 友好，
//! 单测用 Mock 即可跑完整链路）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::blocks::CommandBlock;
use crate::error::AppResult;
use crate::llm::{
    build_client, ChatDelta, ChatMessage, ChatRequest, ChatResponse, DeltaSink, LlmClient,
    ToolSchema,
};
use crate::redact::{RedactionMap, IndexedRedactor};
use crate::risk::{assess_command, gate_of, Gate, RiskLevel};
use crate::sanitize::{self, DEFAULT_MAX_OUTPUT_BYTES};
use crate::shell::ShellKind;
use crate::tools::{all_tools, RunCommandInput, TOOL_RUN_COMMAND, TOOL_SET_PLAN};

/// 内置 system prompt（rssh prompts/general.md 移植 + 品牌化）。
const SYSTEM_PROMPT: &str = include_str!("prompts/general.md");

/// Agent 模式追加的工作方式：先取证、再动手、最后验证。对应 GitHub Copilot
/// Agent 的「理解目标 → 查找 → 制定方案 → 执行 → 验证 → 汇报」六步，
/// 只是把「改文件」换成「在远端主机上执行运维动作」。
const AGENT_PROMPT: &str = "
## Working mode: agent

You are expected to drive the investigation to a conclusion, not just answer:

1. Understand the goal and its constraints (what is allowed to change).
2. Publish your plan first with the `set_plan` tool (2-6 short steps) - the user
   watches it as a checklist, so keep each step to one action.
3. Gather evidence with read-only probes before forming a theory.
4. Decide the smallest change that could fix it.
5. Carry it out through tools (mutating commands still need user approval).
6. Verify: re-run a read-only probe and report what actually changed.
7. Finish with a short report: cause, what you ran, result, and anything left.

Do not invent evidence - if a probe fails, say so and try another one.
Keep every step visible: the user sees your tool calls as a step list.

## 工作方式：代理

要求你把排查推进到结论，而不只是回答：

1. 理解目标与约束（哪些东西允许被改动）。
2. 先用 set_plan 工具发布计划（2-6 条短步骤），用户会把它当成清单实时看着，
   所以一条步骤只对应一个动作。
3. 用只读探测取证，再给出判断。
4. 选择最小改动的修复路径。
5. 通过工具落地（有副作用的命令仍需用户批准）。
6. 验证：再跑一次只读探测，说明实际发生了什么变化。
7. 最后给一份简短汇报：原因、执行过的命令、结果、遗留事项。

不要编造证据；探测失败就明说并换一条路径。每一步都要可见 —— 用户会把你的工具调用看成步骤列表。
";

/// 单次 ask() 内允许的最大工具回合数（防 LLM 无限循环调用工具）。
pub const MAX_TOOL_TURNS: usize = 6;

/// read_remote_file 工具名（FengheShell SFTP/automation 层的 AI 入口）。
pub const TOOL_READ_REMOTE_FILE: &str = "read_remote_file";

// ─── 配置与上下文 ──────────────────────────────────────────────────

/// 参考 GitHub Copilot 的能力分层，在运维场景下的映射：
///
/// - `Ask`：对话层 —— 解释现象、定位原因、给出命令建议，不主动落地改动；
/// - `Agent`：代理层 —— 自己规划步骤、调用工具取证、按权限执行、验证结果并汇报。
///
/// 两者共用同一套工具与 Run Gate，区别只在回合预算与系统提示。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CopilotMode {
    #[default]
    Ask,
    Agent,
}

impl CopilotMode {
    /// 一次 ask() 允许的工具回合数。Ask 只够「取证 + 给建议」，
    /// Agent 才跑得完「取证 → 执行 → 验证」。
    pub fn max_turns(self) -> usize {
        match self {
            CopilotMode::Ask => 2,
            CopilotMode::Agent => MAX_TOOL_TURNS,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CopilotMode::Ask => "ask",
            CopilotMode::Agent => "agent",
        }
    }

    pub fn parse(s: &str) -> Self {
        if s.trim().eq_ignore_ascii_case("agent") {
            CopilotMode::Agent
        } else {
            CopilotMode::Ask
        }
    }

    pub fn is_agent(self) -> bool {
        matches!(self, CopilotMode::Agent)
    }
}

#[derive(Debug, Clone)]
pub struct CopilotConfig {
    /// `openai-completions` / `deepseek-thinking` / `anthropic-messages` / `ollama`。
    pub protocol: String,
    pub endpoint: String,
    pub api_key: String,
    pub model: String,
    pub shell: ShellKind,
    /// 关闭后不做任何脱敏（高级用户的逃生门，默认开）。
    pub redaction_enabled: bool,
    /// 只读命令免点击自动执行（仍发生在用户可见终端里）。
    pub auto_run_readonly: bool,
    /// UI 语言（影响 prompt 的回复语言要求）。
    pub locale: String,
    /// Ask（对话）还是 Agent（代理）。
    pub mode: CopilotMode,
}

impl Default for CopilotConfig {
    fn default() -> Self {
        Self {
            protocol: "openai-completions".into(),
            endpoint: "https://api.openai.com/v1".into(),
            api_key: String::new(),
            model: "gpt-4o-mini".into(),
            shell: ShellKind::default(),
            redaction_enabled: true,
            auto_run_readonly: false,
            locale: "zh-CN".into(),
            mode: CopilotMode::default(),
        }
    }
}

/// 主机硬件快照（FengheShell 资源监控侧栏的同源数据）。
#[derive(Debug, Clone, Default, Serialize)]
pub struct SystemSnapshot {
    pub cpu_usage_pct: f32,
    pub mem_used_bytes: u64,
    pub mem_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub swap_total_bytes: u64,
    pub load_avg: [f64; 3],
    pub disks: Vec<DiskUsage>,
    pub nets: Vec<NetRate>,
    pub top_processes: Vec<ProcInfo>,
    pub sampled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskUsage {
    pub mount: String,
    pub used_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcInfo {
    pub pid: u32,
    pub cpu_pct: f32,
    pub mem_bytes: u64,
    pub command: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetRate {
    pub iface: String,
    pub rx_bytes_per_s: u64,
    pub tx_bytes_per_s: u64,
}

impl SystemSnapshot {
    fn mb(b: u64) -> u64 {
        b / 1024 / 1024
    }

    /// 渲染进 prompt 的紧凑文本段。
    pub fn to_prompt_section(&self) -> String {
        let mut s = String::from("## Host resource snapshot (live from the FengheShell monitor sidebar)\n");
        s.push_str(&format!("- CPU usage: {:.1}%\n", self.cpu_usage_pct));
        s.push_str(&format!(
            "- Memory: {} / {} MB used\n",
            Self::mb(self.mem_used_bytes),
            Self::mb(self.mem_total_bytes)
        ));
        if self.swap_total_bytes > 0 {
            s.push_str(&format!(
                "- Swap: {} / {} MB used\n",
                Self::mb(self.swap_used_bytes),
                Self::mb(self.swap_total_bytes)
            ));
        }
        s.push_str(&format!(
            "- Load average: {:.2} {:.2} {:.2}\n",
            self.load_avg[0], self.load_avg[1], self.load_avg[2]
        ));
        for d in &self.disks {
            let pct = if d.total_bytes > 0 {
                d.used_bytes as f64 / d.total_bytes as f64 * 100.0
            } else {
                0.0
            };
            s.push_str(&format!(
                "- Disk {}: {} / {} MB ({:.1}%)\n",
                d.mount,
                Self::mb(d.used_bytes),
                Self::mb(d.total_bytes),
                pct
            ));
        }
        for n in &self.nets {
            s.push_str(&format!(
                "- Net {}: rx {} B/s, tx {} B/s\n",
                n.iface, n.rx_bytes_per_s, n.tx_bytes_per_s
            ));
        }
        if !self.top_processes.is_empty() {
            s.push_str("- Top processes (cpu):\n");
            for p in self.top_processes.iter().take(8) {
                s.push_str(&format!(
                    "  - pid {pid} {cpu:.1}% cpu {mem}MB `{cmd}`\n",
                    pid = p.pid,
                    cpu = p.cpu_pct,
                    mem = Self::mb(p.mem_bytes),
                    cmd = p.command
                ));
            }
        }
        s.push('\n');
        s
    }
}

/// 触发方式：用户提问 / 监控阈值自动触发（CPU 飙高、OOM 风险…）。
#[derive(Debug, Clone)]
pub enum Trigger {
    /// 用户在 AI 抽屉主动提问。
    User,
    /// 监控事件自动触发，附带人类可读的原因。
    Monitor(String),
}

/// 一次诊断的全部输入。
#[derive(Debug, Clone)]
pub struct TriageContext {
    pub question: String,
    /// 最近的命令块（OSC 133 上下文，推荐 `ContextWindow::blocks()` 的尾部）。
    pub blocks: Vec<CommandBlock>,
    pub system: Option<SystemSnapshot>,
    pub shell: ShellKind,
    pub trigger: Trigger,
}

// ─── 输出模型 ──────────────────────────────────────────────────────

/// 一条被 AI 提议的命令（UI 渲染成操作卡片）。
#[derive(Debug, Clone)]
pub struct ProposedCommand {
    /// 卡片唯一 id（UI 键 + 工具调用关联）。
    pub id: String,
    /// 还原脱敏后的真实命令（可直接填入/执行）。
    pub cmd: String,
    /// 脱敏态命令（回传给 LLM 的历史里用）。
    pub cmd_redacted: String,
    pub explain: String,
    pub side_effect: String,
    pub risk: RiskLevel,
    pub gate: Gate,
    /// shape validator 拒绝时的原因（None = 放行）。
    pub blocked_reason: Option<String>,
    /// 审批后的执行结果（None = 尚未执行 / 被拒 / 被拦截）。
    pub outcome: Option<CommandOutcome>,
    /// 用户/策略的最终处置。
    pub disposition: Disposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// 等待用户点击。
    Pending,
    /// 已一键执行（绿灯）。
    Executed,
    /// 已填入终端待用户回车（橙/红灯）。
    FilledForManualRun,
    /// 被拒绝。
    Rejected,
    /// 被 shape validator 硬拦截，未到用户面前。
    Blocked,
}

/// 一次（被批准的）命令执行的出口。
#[derive(Debug, Clone)]
pub struct CommandOutcome {
    pub exit_code: Option<i32>,
    pub output: String,
    pub timed_out: bool,
}

/// Agent 计划清单里一条步骤的状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStepState {
    /// 还没轮到。
    Pending,
    /// 正在执行（清单里排在最前面的未完成步骤）。
    Running,
    /// 对应的一次工具调用成功了。
    Done,
    /// 对应的一次工具调用失败/被拦下。
    Failed,
}

impl PlanStepState {
    pub fn as_str(self) -> &'static str {
        match self {
            PlanStepState::Pending => "pending",
            PlanStepState::Running => "running",
            PlanStepState::Done => "done",
            PlanStepState::Failed => "failed",
        }
    }
}

/// Agent 计划清单里的一条步骤。
#[derive(Debug, Clone, Serialize)]
pub struct PlanStep {
    pub text: String,
    pub state: PlanStepState,
}

/// 工具调用痕迹（UI 时间线 + 调试）。
#[derive(Debug, Clone)]
pub struct ToolLogEntry {
    pub tool: String,
    pub summary: String,
    pub is_error: bool,
    pub at: DateTime<Utc>,
}

/// 计划清单的推进规则：第 n 次工具调用的结果决定第 n 步的状态。
///
/// 这是有意做的简化 —— 让模型每次都回报「哪些步骤完成了」既啰嗦又不可靠，
/// 而一份计划里的步骤与实际行动基本是一一对应的。清单只用于**展示进度**，
/// 真正的执行结果仍然以命令卡片和步骤痕迹为准。
fn advance_plan(plan: &mut Vec<PlanStep>, failed: bool) {
    if plan.is_empty() {
        return;
    }
    let idx = plan
        .iter()
        .position(|s| s.state == PlanStepState::Running)
        .unwrap_or_else(|| plan.len());
    if let Some(step) = plan.get_mut(idx) {
        step.state = if failed {
            PlanStepState::Failed
        } else {
            PlanStepState::Done
        };
    }
    // 下一步进入进行中。
    if let Some(next) = plan.get_mut(idx + 1) {
        if next.state == PlanStepState::Pending {
            next.state = PlanStepState::Running;
        }
    }
}


/// 补全层（对应 GitHub Copilot 的代码补全）：给一个还没敲完的命令前缀，
/// 预测「后面应该接什么」。刻意做得又小又快 —— 不带工具、不流式、
/// `max_tokens` 只有 64，所以一次补全只花几十个 token。
const COMPLETION_PROMPT: &str = r#"You complete shell commands for an ops terminal.

Rules:
- Output ONLY the completion - no explanation, no markdown fence, no quotes.
- Do not repeat the prefix that is already typed.
- Prefer read-only, non-destructive commands; never suggest rm/mkfs/dd/shutdown.
- Keep it a single line and syntactically valid POSIX shell.
- If you cannot do better than the prefix itself, output an empty string.

你是一个运维终端的命令补全器。

规则：
- 只输出补全内容，不要解释、不要代码块、不要引号。
- 不要重复用户已经输入的前缀。
- 优先只读、无破坏性的命令；绝不给出 rm / mkfs / dd / shutdown。
- 保持单行且是合法的 POSIX shell。
- 如果给不出比前缀更好的结果，就输出空字符串。
"#;

/// 一次补全请求的上下文（可选）：让模型知道目标主机的大致情况。
#[derive(Debug, Clone, Default)]
pub struct CompletionContext {
    /// 最近执行过的命令（最早 → 最新），只取尾部几条。
    pub recent_commands: Vec<String>,
    /// 当前工作目录（OSC 7 拿到时）。
    pub cwd: Option<String>,
}

impl CompletionContext {
    fn as_prompt(&self) -> String {
        let mut s = String::new();
        if let Some(cwd) = &self.cwd {
            s.push_str(&format!("cwd: {cwd}\n"));
        }
        if !self.recent_commands.is_empty() {
            s.push_str("recent commands:\n");
            for cmd in self.recent_commands.iter().rev().take(5) {
                s.push_str(&format!("- {cmd}\n"));
            }
        }
        s
    }
}

/// 把模型回的补全清洗成可以嵌在输入后面的纯文本：丢掉代码块围栏、引号、解释性前缀，
/// 只留第一行，并去掉模型「顺手重复」的前缀。
fn clean_completion(raw: &str, prefix: &str) -> String {
    let mut text = raw.trim().to_string();
    // ```sh\ncmd\n```
    if text.starts_with("```") {
        text = text
            .trim_start_matches('`')
            .lines()
            .skip_while(|l| !l.trim().is_empty() && l.trim().chars().all(|c| !c.is_whitespace()) && !l.contains(' '))
            .collect::<Vec<_>>()
            .join("\n");
        text = text.replace("```", "");
    }
    // 只要第一行：补全不该跨行。
    let first = text.lines().next().unwrap_or("").trim().to_string();
    let mut out = first
        .trim_matches('`')
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string();
    // 模型偶尔把前缀又写一遍。
    if prefix.ends_with(' ') || prefix.ends_with('|') {
        // 前缀以分隔符结尾时，若补全以同样的前缀开头，去掉重复部分。
        if let Some(rest) = out.strip_prefix(prefix.trim_end()) {
            out = rest.trim_start().to_string();
        }
    }
    out
}


/// 一次 ask() 的总输出。
#[derive(Debug, Clone)]
pub struct TriageOutcome {
    /// LLM 最终文本（已反向脱敏还原）。
    pub text: String,
    pub proposed: Vec<ProposedCommand>,
    /// Agent 模式下的计划清单（Ask 模式恒为空）。
    pub plan: Vec<PlanStep>,
    pub tool_log: Vec<ToolLogEntry>,
    /// 本次脱敏映射（UI 若要展示「还原视图」可用；敏感，不外泄）。
    pub redaction_map: RedactionMap,
    pub tokens_in: Option<u32>,
    pub tokens_out: Option<u32>,
}

// ─── 执行后端 trait（FengheShell 侧实现） ────────────────────────────

/// AI 的副作用执行面。FengheShell 实现它：
///
/// - `request_approval`：把命令卡片推给 UI 抽屉，等待用户点击
///   （绿灯自动批准由 `auto_run_readonly` 在引擎侧处理，不会调用到这里）。
/// - `execute_approved`：把命令写入会话 PTY（带 sentinel 回显退出码），
///   等 OSC 133 D 标记或 sentinel 抓取退出码与输出。
/// - `read_remote_file`：走 SFTP/automation 层读远程文件（有字节上限）。
#[async_trait]
pub trait ToolRuntime: Send + Sync {
    async fn request_approval(&self, proposal: &ProposedCommand) -> AppResult<bool>;
    async fn execute_approved(&self, proposal: &ProposedCommand) -> AppResult<CommandOutcome>;
    async fn read_remote_file(&self, path: &str, max_bytes: usize) -> AppResult<String>;
}

// ─── 引擎 ──────────────────────────────────────────────────────────

pub struct TriageEngine {
    cfg: CopilotConfig,
    client: Box<dyn LlmClient>,
    runtime: Arc<dyn ToolRuntime>,
    redactor: IndexedRedactor,
    /// 宿主持有同一个开关：置位后引擎在下一个回合边界退出，客户端也在下一个
    /// 流式分块处放弃请求（用户点了「停止」）。
    cancel: Arc<AtomicBool>,
}

impl TriageEngine {
    pub fn new(cfg: CopilotConfig, runtime: Arc<dyn ToolRuntime>) -> AppResult<Self> {
        let client = build_client(&cfg.protocol, cfg.api_key.clone(), cfg.endpoint.clone())?;
        Ok(Self {
            cfg,
            client,
            runtime,
            redactor: IndexedRedactor::builtin(),
            cancel: Arc::new(AtomicBool::new(false)),
        })
    }

    /// 使用自定义脱敏规则集构造（用户配置驱动）。
    pub fn with_redactor(mut self, redactor: IndexedRedactor) -> Self {
        self.redactor = redactor;
        self
    }

    /// 交给宿主一个中断开关：置位后这次 ask() 会尽快结束并返回 `llm_cancelled`。
    pub fn with_cancel(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.cancel = cancel;
        self
    }

    pub fn config(&self) -> &CopilotConfig {
        &self.cfg
    }

    /// 补全层：给一个命令前缀，返回「后面应该接什么」—— 只返回**补全部分**，
    /// 不含用户已经输入的前缀。失败或模型无话可说时返回空串，调用方直接不显示即可。
    pub async fn complete(
        &self,
        prefix: &str,
        ctx: &CompletionContext,
    ) -> AppResult<String> {
        let prefix = prefix.trim_end();
        if prefix.trim().is_empty() {
            return Ok(String::new());
        }
        let req = ChatRequest {
            system_prompt: COMPLETION_PROMPT.to_string(),
            messages: vec![ChatMessage::User {
                content: format!(
                    "{}\nComplete this command:\n{}",
                    ctx.as_prompt(),
                    prefix
                ),
            }],
            tools: Vec::new(),
            model: self.cfg.model.clone(),
            max_tokens: 64,
            cancel: Some(self.cancel.clone()),
        };
        let noop: DeltaSink = Arc::new(|_| {});
        let resp = self.client.chat(req, noop).await?;
        Ok(clean_completion(&resp.text, prefix))
    }

    /// 跑一轮完整诊断。
    pub async fn ask(
        &self,
        ctx: &TriageContext,
        sink: Option<DeltaSink>,
    ) -> AppResult<TriageOutcome> {
        let noop: DeltaSink = Arc::new(|_| {});
        let sink = sink.unwrap_or(noop);
        let mut map = RedactionMap::new();
        let redact = |s: &str, map: &mut RedactionMap| -> String {
            if self.cfg.redaction_enabled {
                self.redactor.apply(s, map)
            } else {
                s.to_string()
            }
        };

        let system = redact(&self.build_system_prompt(ctx), &mut map);
        let user = redact(&self.build_user_message(ctx), &mut map);
        let mut messages = vec![ChatMessage::User { content: user }];
        let mut proposed: Vec<ProposedCommand> = Vec::new();
        let mut plan: Vec<PlanStep> = Vec::new();
        let mut tool_log: Vec<ToolLogEntry> = Vec::new();
        let mut final_resp: Option<ChatResponse> = None;

        for _ in 0..self.cfg.mode.max_turns() {
            // 回合边界的中断检查：即使客户端还在等第一个分块，也能立刻退出。
            if self.cancel.load(Ordering::Relaxed) {
                return Err(crate::llm::cancelled_error());
            }
            let req = ChatRequest {
                system_prompt: system.clone(),
                messages: messages.clone(),
                tools: self.tools(),
                model: self.cfg.model.clone(),
                max_tokens: 4096,
                cancel: Some(self.cancel.clone()),
            };
            let resp = self.client.chat(req, sink.clone()).await?;
            if resp.tool_calls.is_empty() {
                final_resp = Some(resp);
                break;
            }
            // assistant 轮次（含 reasoning 回传，DeepSeek 需要）
            messages.push(ChatMessage::Assistant {
                content: redact(&resp.text, &mut map),
                tool_calls: resp.tool_calls.clone(),
                reasoning_content: resp.reasoning_content.clone(),
            });
            for call in &resp.tool_calls {
                let (content, is_error, summary) = self
                    .execute_tool(call, &mut proposed, &mut map, &mut plan, &sink)
                    .await;
                // 计划清单按「第 n 次**动作型**工具调用对应第 n 步」推进：成功置
                // done，失败/被拦下置 failed，并把下一步标成进行中。
                // set_plan 自己不算一步，否则刚发布就推进一格。
                if call.name.as_str() != TOOL_SET_PLAN {
                    advance_plan(&mut plan, is_error);
                    (sink)(ChatDelta::Plan(plan.clone()));
                }
                tool_log.push(ToolLogEntry {
                    tool: call.name.clone(),
                    summary,
                    is_error,
                    at: Utc::now(),
                });
                messages.push(ChatMessage::ToolResult {
                    tool_call_id: call.id.clone(),
                    content,
                    is_error,
                    pre_redacted: false,
                });
            }
        }

        let resp = final_resp.unwrap_or_else(|| ChatResponse {
            text: String::new(),
            tool_calls: Vec::new(),
            stop_reason: "max_turns".into(),
            tokens_in: None,
            tokens_out: None,
            reasoning_content: None,
        });

        // 命令卡片在交到 UI/PTY 之前必须还原真实值。
        for p in &mut proposed {
            p.cmd = map.restore(&p.cmd);
        }

        // 收尾时把「进行中」的状态收干净：要么 done，要么 failed。
        for step in &mut plan {
            if step.state == PlanStepState::Running {
                step.state = PlanStepState::Done;
            }
        }
        Ok(TriageOutcome {
            text: map.restore(&resp.text),
            proposed,
            plan: plan.clone(),
            tool_log,
            redaction_map: map,
            tokens_in: resp.tokens_in,
            tokens_out: resp.tokens_out,
        })
    }

    fn build_system_prompt(&self, ctx: &TriageContext) -> String {
        let mut s = String::from(SYSTEM_PROMPT);
        s.push_str("\n\n---\n\n");
        s.push_str(&ctx.shell.prompt_section());
        s.push_str(&format!(
            "\n# Session notes\n\n- Reply in the user's locale: {}.\n- You are running inside FengheShell's built-in AI copilot drawer.\n- Available tools in THIS environment: `run_command` and `read_remote_file` only. Do not call any other tool name.\n",
            self.cfg.locale
        ));
        if let Some(snap) = &ctx.system {
            s.push('\n');
            s.push_str(&snap.to_prompt_section());
        }
        if self.cfg.mode.is_agent() {
            s.push_str(AGENT_PROMPT);
        }
        s
    }

    fn build_user_message(&self, ctx: &TriageContext) -> String {
        let mut s = String::new();
        match &ctx.trigger {
            Trigger::User => {}
            Trigger::Monitor(reason) => {
                s.push_str(&format!(
                    "[AUTOMATIC TRIAGE] FengheShell's monitor sidebar detected: {reason}. The user has NOT asked a question — open with what the snapshot says, then propose the first read-only probe.\n\n"
                ));
            }
        }
        if !ctx.blocks.is_empty() {
            s.push_str("Recent terminal context (command blocks, oldest → newest):\n```\n");
            let mut transcript = String::new();
            for b in &ctx.blocks {
                let exit = b
                    .exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "?".into());
                transcript.push_str(&format!(
                    "$ {}\n[exit {exit}]\n{}\n",
                    b.command, b.output
                ));
            }
            let t = sanitize::truncate(&transcript, DEFAULT_CONTEXT_BYTES_FOR_PROMPT);
            s.push_str(&t.text);
            s.push_str("\n```\n\n");
        }
        s.push_str(&ctx.question);
        s
    }

    fn tools(&self) -> Vec<ToolSchema> {
        let mut v: Vec<ToolSchema> = all_tools()
            .into_iter()
            .filter(|t| t.name == TOOL_RUN_COMMAND)
            .collect();
        // 计划清单只在 Agent 模式暴露：Ask 模式下没有「多步推进」这回事。
        if self.cfg.mode.is_agent() {
            v.extend(all_tools().into_iter().filter(|t| t.name == TOOL_SET_PLAN));
        }
        v.push(ToolSchema {
            name: TOOL_READ_REMOTE_FILE.into(),
            description: "Read a remote text file through the SFTP/automation layer (bounded bytes). Use it to inspect logs and configs without leaving the drawer.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute remote path" },
                    "max_bytes": { "type": "integer", "description": "Cap, default 65536" }
                },
                "required": ["path"]
            }),
        });
        v
    }

    /// 执行一个工具调用。返回 (tool_result 内容, is_error, 时间线摘要)。
    ///
    /// `plan` 是 Agent 的计划清单：工具调用按出现顺序逐条推进它的状态，
    /// 每次变化都会通过 `sink` 推给 UI，所以用户看到的是实时清单而不是
    /// 事后回放。
    async fn execute_tool(
        &self,
        call: &crate::llm::ToolCall,
        proposed: &mut Vec<ProposedCommand>,
        map: &mut RedactionMap,
        plan: &mut Vec<PlanStep>,
        sink: &crate::llm::DeltaSink,
    ) -> (String, bool, String) {
        let redact = |s: &str, map: &mut RedactionMap| -> String {
            if self.cfg.redaction_enabled {
                self.redactor.apply(s, map)
            } else {
                s.to_string()
            }
        };
        match call.name.as_str() {
            // 计划清单：只写 UI，不碰主机。
            TOOL_SET_PLAN => {
                let steps: Vec<String> = call
                    .input
                    .get("steps")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|s| s.as_str().map(str::to_string))
                            .filter(|s| !s.trim().is_empty())
                            .take(8)
                            .collect()
                    })
                    .unwrap_or_default();
                if steps.is_empty() {
                    return ("set_plan needs a non-empty `steps` array".into(), true, "empty plan".into());
                }
                *plan = steps
                    .into_iter()
                    .map(|text| PlanStep {
                        text,
                        state: PlanStepState::Pending,
                    })
                    .collect();
                // 第一条标记为进行中，用户立刻知道从哪一步开始。
                if let Some(first) = plan.first_mut() {
                    first.state = PlanStepState::Running;
                }
                (sink)(ChatDelta::Plan(plan.clone()));
                return (
                    format!("plan published: {} steps. Follow it in order.", plan.len()),
                    false,
                    format!("planned {} steps", plan.len()),
                );
            }
            TOOL_RUN_COMMAND => {
                let input: RunCommandInput = match serde_json::from_value(call.input.clone()) {
                    Ok(i) => i,
                    Err(e) => {
                        return (
                            format!("invalid run_command input: {e}"),
                            true,
                            "invalid input".into(),
                        )
                    }
                };
                // AI 看到的是脱敏后的上下文，它可能把占位符原样写回命令。
                // 真正要落地的命令必须先在本地还原 —— 后面的 shape validator
                // 也只认还原后的形态：`<INTERNAL_IP_1>` 里的尖括号会被 tree-sitter
                // 当成重定向节点，不还原就把一条无害的探测命令误杀。
                let real_cmd = map.restore(&input.cmd);
                // 墙 1：shape validator（rssh 移植）
                if let Err(e) =
                    sanitize::validate_with(&real_cmd, &sanitize::Blacklist::builtin())
                {
                    let reason = crate::risk::shape_reason(&e);
                    // 被拦下的命令也要留在提议列表里：用户得看得见 AI 刚才想干什么。
                    proposed.push(ProposedCommand {
                        id: format!("cmd-{}", proposed.len() + 1),
                        cmd: real_cmd.clone(),
                        cmd_redacted: redact(&real_cmd, map),
                        explain: input.explain.clone(),
                        side_effect: input.side_effect.clone(),
                        risk: RiskLevel::Destructive,
                        gate: Gate::Blocked,
                        blocked_reason: Some(reason.clone()),
                        outcome: None,
                        disposition: Disposition::Pending,
                    });
                    return (
                        format!("fengheshell refused the command: {reason}. Propose a different, read-only approach."),
                        true,
                        format!("blocked: {}", input.cmd.chars().take(60).collect::<String>()),
                    );
                }
                // 墙 2：风险分级
                let assessment = assess_command(&real_cmd);
                let gate = gate_of(&assessment);
                let id = format!("cmd-{}", proposed.len() + 1);
                let mut proposal = ProposedCommand {
                    id: id.clone(),
                    cmd: real_cmd.clone(),
                    cmd_redacted: redact(&real_cmd, map),
                    explain: input.explain.clone(),
                    side_effect: input.side_effect.clone(),
                    risk: assessment.level,
                    gate,
                    blocked_reason: assessment.blocked.clone(),
                    outcome: None,
                    disposition: Disposition::Pending,
                };

                // 墙 3：Human-in-the-Loop。绿灯 + auto_run_readonly 时策略放行。
                let auto_ok =
                    self.cfg.auto_run_readonly && assessment.level == RiskLevel::ReadOnly;
                let approved = if auto_ok {
                    true
                } else {
                    match self.runtime.request_approval(&proposal).await {
                        Ok(v) => v,
                        Err(e) => {
                            return (format!("approval channel failed: {e}"), true, e.to_string())
                        }
                    }
                };
                if !approved {
                    proposal.disposition = Disposition::Rejected;
                    proposed.push(proposal);
                    return (
                        format!(
                            "user rejected the command: {}. Adjust based on their reason or wait for their input.",
                            redact(&real_cmd, map)
                        ),
                        true,
                        "user rejected".into(),
                    );
                }

                // 墙 4：在用户可见的 PTY 执行（FengheShell 侧实现）。
                // proposal.cmd 已是还原后的真实命令（见墙 1 上方的 restore）。
                let exec_proposal = proposal.clone();
                match self.runtime.execute_approved(&exec_proposal).await {
                    Ok(outcome) => {
                        let t = sanitize::truncate(&outcome.output, DEFAULT_MAX_OUTPUT_BYTES);
                        let exit = outcome
                            .exit_code
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "?".into());
                        let content = redact(
                            &format!("exit_code: {exit}\noutput:\n{}", t.text),
                            map,
                        );
                        proposal.outcome = Some(outcome);
                        proposal.disposition = Disposition::Executed;
                        proposed.push(proposal);
                        let summary: String = input.cmd.chars().take(60).collect();
                        (content, false, format!("ran: {summary}"))
                    }
                    Err(e) => {
                        proposal.disposition = Disposition::Rejected;
                        proposed.push(proposal);
                        (
                            format!("command execution failed: {e}"),
                            true,
                            "execution failed".into(),
                        )
                    }
                }
            }
            TOOL_READ_REMOTE_FILE => {
                let path = call
                    .input
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let max_bytes = call
                    .input
                    .get("max_bytes")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(65_536) as usize;
                match self.runtime.read_remote_file(&path, max_bytes).await {
                    Ok(content) => {
                        let t = sanitize::truncate(&content, DEFAULT_MAX_OUTPUT_BYTES);
                        let content = redact(&t.text, map);
                        (
                            format!("path: {path}\ncontent:\n{content}"),
                            false,
                            format!("read {path}"),
                        )
                    }
                    Err(e) => (
                        format!("read_remote_file failed for {path}: {e}"),
                        true,
                        format!("read {path} failed"),
                    ),
                }
            }
            other => (
                format!(
                    "tool `{other}` is not available in this environment. Use run_command or read_remote_file."
                ),
                true,
                format!("unsupported tool {other}"),
            ),
        }
    }
}

/// prompt 里终端上下文的额外收紧（比 ContextWindow 的 8KB 更保守，
/// 因为还有系统快照和问题本身要占预算）。
const DEFAULT_CONTEXT_BYTES_FOR_PROMPT: usize = 8 * 1024;

/// 供 UI/PTY 侧构造「带 sentinel 的完整命令行」：
/// POSIX: `<cmd>; echo "<MARKER>:$?"`，退出码通过 D 标记或 sentinel 抓取。
pub fn sentinel_wrap(cmd: &str, shell: ShellKind, marker: &str) -> String {
    shell.format_sentinel(cmd, marker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::Gate;

    /// 记录请求并全部批准的 Mock runtime。
    #[derive(Default)]
    struct MockRuntime {
        approved: std::sync::atomic::AtomicBool,
        run_log: std::sync::Mutex<Vec<String>>,
        files: std::sync::Mutex<Vec<(String, String)>>,
    }

    #[async_trait]
    impl ToolRuntime for MockRuntime {
        async fn request_approval(&self, _p: &ProposedCommand) -> AppResult<bool> {
            Ok(self.approved.load(std::sync::atomic::Ordering::SeqCst))
        }
        async fn execute_approved(&self, p: &ProposedCommand) -> AppResult<CommandOutcome> {
            self.run_log.lock().unwrap().push(p.cmd.clone());
            Ok(CommandOutcome {
                exit_code: Some(0),
                output: "mock output".into(),
                timed_out: false,
            })
        }
        async fn read_remote_file(&self, path: &str, _max: usize) -> AppResult<String> {
            let files = self.files.lock().unwrap();
            Ok(files
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, c)| c.clone())
                .unwrap_or_else(|| "not found".into()))
        }
    }

    /// 按脚本返回 tool_calls 的 Mock LLM。
    struct MockLlm {
        script: std::sync::Mutex<Vec<ChatResponse>>,
    }

    #[async_trait]
    impl LlmClient for MockLlm {
        async fn chat(&self, _req: ChatRequest, _sink: DeltaSink) -> AppResult<ChatResponse> {
            let mut s = self.script.lock().unwrap();
            if s.len() > 1 {
                Ok(s.remove(0))
            } else {
                Ok(s[0].clone())
            }
        }
        async fn list_models(&self) -> AppResult<Vec<crate::llm::ModelInfo>> {
            Ok(vec![])
        }
    }

    fn tool_call(id: &str, name: &str, input: serde_json::Value) -> crate::llm::ToolCall {
        crate::llm::ToolCall {
            id: id.into(),
            name: name.into(),
            input,
        }
    }

    fn resp_with_tools(tools: Vec<crate::llm::ToolCall>) -> ChatResponse {
        ChatResponse {
            text: "thinking...".into(),
            tool_calls: tools,
            stop_reason: "tool_use".into(),
            tokens_in: Some(1),
            tokens_out: Some(1),
            reasoning_content: None,
        }
    }

    fn resp_final(text: &str) -> ChatResponse {
        ChatResponse {
            text: text.into(),
            tool_calls: vec![],
            stop_reason: "stop".into(),
            tokens_in: Some(1),
            tokens_out: Some(1),
            reasoning_content: None,
        }
    }

    fn engine(script: Vec<ChatResponse>, runtime: Arc<MockRuntime>) -> TriageEngine {
        TriageEngine {
            cfg: CopilotConfig::default(),
            client: Box::new(MockLlm {
                script: std::sync::Mutex::new(script),
            }),
            runtime,
            redactor: IndexedRedactor::builtin(),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    #[tokio::test]
    async fn agent_plan_is_published_and_advances_with_each_step() {
        use std::sync::Mutex;

        let rt = Arc::new(MockRuntime::default());
        rt.approved.store(true, std::sync::atomic::Ordering::SeqCst);
        let plan_steps: Vec<String> = vec![
            "看 CPU 占用".into(),
            "找出占 CPU 最高的进程".into(),
            "确认它是否异常".into(),
        ];
        let eng = engine(
            vec![
                resp_with_tools(vec![tool_call(
                    "p1",
                    TOOL_SET_PLAN,
                    serde_json::json!({ "steps": plan_steps }),
                )]),
                resp_with_tools(vec![tool_call(
                    "t1",
                    TOOL_RUN_COMMAND,
                    serde_json::json!({"cmd": "ps aux --sort=-%cpu | head -n 5", "explain": "看占用", "side_effect": "无"}),
                )]),
                resp_final("结论".into()),
            ],
            rt.clone(),
        );
        let seen: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_seen = seen.clone();
        let sink: DeltaSink = Arc::new(move |delta| {
            if let ChatDelta::Plan(steps) = delta {
                sink_seen
                    .lock()
                    .unwrap()
                    .push(steps.iter().map(|s| s.text.clone()).collect());
            }
        });
        // 切到 Agent：Ask 模式下 set_plan 工具根本不会被暴露。
        let mut cfg = CopilotConfig::default();
        cfg.mode = CopilotMode::Agent;
        let eng = {
            let mut e = eng;
            e.cfg = cfg;
            e
        };
        let out = eng.ask(&ctx(), Some(sink)).await.unwrap();
        assert_eq!(out.plan.len(), 3);
        assert_eq!(out.plan[0].text, "看 CPU 占用");
        // 一次成功调用推进一步：第一步 done，第二步 running。
        assert_eq!(out.plan[0].state, PlanStepState::Done);
        assert_eq!(out.plan[1].state, PlanStepState::Done, "收尾时 running 也会被收干净");
        assert_eq!(out.plan[2].state, PlanStepState::Pending);
        // 实时推送至少两帧：发布计划 + 推进一次。
        let frames = seen.lock().unwrap().len();
        assert!(frames >= 2, "计划变化要实时推给 UI，实际 {frames} 帧");
    }

    #[test]
    fn completion_is_stripped_down_to_the_missing_part() {
        // 代码块围栏 + 引号都要清掉。
        assert_eq!(clean_completion("```sh\nps aux --sort=-%cpu\n```", ""), "ps aux --sort=-%cpu");
        assert_eq!(clean_completion("\" | head -n 10\"", ""), "| head -n 10");
        // 只取第一行。
        assert_eq!(clean_completion("df -h\nexplanation here", ""), "df -h");
        // 模型把前缀又写了一遍时去掉重复。
        assert_eq!(clean_completion("ps aux | head -n 10", "ps aux | "), "head -n 10");
        // 空输入 → 空结果。
        assert_eq!(clean_completion("   ", ""), "");
    }

    #[test]
    fn completion_context_renders_recent_commands_newest_first() {
        let ctx = CompletionContext {
            recent_commands: vec!["uptime".into(), "df -h".into(), "free -m".into()],
            cwd: Some("/var/log".into()),
        };
        let rendered = ctx.as_prompt();
        assert!(rendered.contains("cwd: /var/log"));
        assert!(rendered.find("free -m").unwrap() < rendered.find("df -h").unwrap());
        assert!(rendered.find("df -h").unwrap() < rendered.find("uptime").unwrap());
    }

    #[test]
    fn agent_mode_gets_the_full_tool_budget() {
        assert_eq!(CopilotMode::Ask.max_turns(), 2);
        assert_eq!(CopilotMode::Agent.max_turns(), MAX_TOOL_TURNS);
        assert!(CopilotMode::Agent.max_turns() > CopilotMode::Ask.max_turns());
        // 未知字符串一律回落到更保守的 Ask。
        assert_eq!(CopilotMode::parse("agent"), CopilotMode::Agent);
        assert_eq!(CopilotMode::parse("AGENT"), CopilotMode::Agent);
        assert_eq!(CopilotMode::parse(""), CopilotMode::Ask);
        assert_eq!(CopilotMode::parse("whatever"), CopilotMode::Ask);
        assert_eq!(CopilotMode::default(), CopilotMode::Ask);
    }

    #[tokio::test]
    async fn a_cancelled_round_stops_before_the_next_turn() {
        let rt = Arc::new(MockRuntime::default());
        rt.approved.store(true, std::sync::atomic::Ordering::SeqCst);
        let cancel = Arc::new(AtomicBool::new(false));
        let eng = engine(
            vec![
                resp_with_tools(vec![tool_call(
                    "t1",
                    TOOL_RUN_COMMAND,
                    serde_json::json!({"cmd": "df -h", "explain": "看磁盘", "side_effect": "无"}),
                )]),
                resp_final("不该走到这里"),
            ],
            rt.clone(),
        )
        .with_cancel(cancel.clone());
        cancel.store(true, Ordering::Relaxed);
        let err = eng.ask(&ctx(), None).await.expect_err("取消必须报错");
        assert_eq!(err.code(), "llm_cancelled");
        assert!(rt.run_log.lock().unwrap().is_empty(), "取消后不得再执行命令");
    }

    fn ctx() -> TriageContext {
        TriageContext {
            question: "为什么 CPU 这么高？".into(),
            blocks: vec![CommandBlock {
                command: "curl 10.0.0.5/api".into(),
                output: "connection refused".into(),
                exit_code: Some(7),
                started_at: Utc::now(),
                finished_at: Some(Utc::now()),
                cwd: None,
                finished: true,
            }],
            system: Some(SystemSnapshot {
                cpu_usage_pct: 99.0,
                mem_used_bytes: 6 * 1024 * 1024 * 1024,
                mem_total_bytes: 8 * 1024 * 1024 * 1024,
                ..Default::default()
            }),
            shell: ShellKind::default(),
            trigger: Trigger::User,
        }
    }

    #[tokio::test]
    async fn readonly_command_gets_direct_run_and_executes() {
        let rt = Arc::new(MockRuntime::default());
        rt.approved.store(true, std::sync::atomic::Ordering::SeqCst);
        let eng = engine(
            vec![
                resp_with_tools(vec![tool_call(
                    "t1",
                    TOOL_RUN_COMMAND,
                    serde_json::json!({"cmd": "ps aux --sort=-%cpu | head -n 5", "explain": "看占用", "side_effect": "无"}),
                )]),
                resp_final("CPU 被进程 1234 占满"),
            ],
            rt.clone(),
        );
        let out = eng.ask(&ctx(), None).await.unwrap();
        assert_eq!(out.proposed.len(), 1);
        assert_eq!(out.proposed[0].risk, RiskLevel::ReadOnly);
        assert_eq!(out.proposed[0].gate, Gate::DirectRun);
        assert_eq!(out.proposed[0].disposition, Disposition::Executed);
        assert_eq!(rt.run_log.lock().unwrap()[0], "ps aux --sort=-%cpu | head -n 5");
        assert_eq!(out.text, "CPU 被进程 1234 占满");
    }

    #[tokio::test]
    async fn mutating_command_is_fill_only_and_rejected_proposal_is_reported() {
        let rt = Arc::new(MockRuntime::default());
        // 拒绝批准
        rt.approved.store(false, std::sync::atomic::Ordering::SeqCst);
        let eng = engine(
            vec![
                resp_with_tools(vec![tool_call(
                    "t1",
                    TOOL_RUN_COMMAND,
                    serde_json::json!({"cmd": "systemctl restart nginx", "explain": "重启", "side_effect": "服务瞬断"}),
                )]),
                resp_final("好的，等你手动执行"),
            ],
            rt.clone(),
        );
        let out = eng.ask(&ctx(), None).await.unwrap();
        assert_eq!(out.proposed.len(), 1);
        assert_eq!(out.proposed[0].risk, RiskLevel::Mutating);
        assert_eq!(out.proposed[0].gate, Gate::FillTerminal);
        assert_eq!(out.proposed[0].disposition, Disposition::Rejected);
        assert!(rt.run_log.lock().unwrap().is_empty(), "被拒的命令不得执行");
    }

    #[tokio::test]
    async fn destructive_command_is_blocked_before_user() {
        let rt = Arc::new(MockRuntime::default());
        rt.approved.store(true, std::sync::atomic::Ordering::SeqCst);
        let eng = engine(
            vec![
                resp_with_tools(vec![tool_call(
                    "t1",
                    TOOL_RUN_COMMAND,
                    serde_json::json!({"cmd": "rm -rf /var/log/nginx", "explain": "清日志", "side_effect": "不可恢复"}),
                )]),
                resp_final("该命令被内置校验拒绝"),
            ],
            rt.clone(),
        );
        let out = eng.ask(&ctx(), None).await.unwrap();
        assert_eq!(out.proposed.len(), 1);
        assert_eq!(out.proposed[0].gate, Gate::Blocked);
        assert!(out.proposed[0].blocked_reason.is_some());
        assert!(rt.run_log.lock().unwrap().is_empty(), "被拦截命令不得执行");
        assert_eq!(out.proposed[0].disposition, Disposition::Pending);
    }

    #[tokio::test]
    async fn auto_run_readonly_skips_approval() {
        let rt = Arc::new(MockRuntime::default());
        // approved=false，但 auto_run_readonly 应放行只读命令
        rt.approved.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut eng = engine(
            vec![
                resp_with_tools(vec![tool_call(
                    "t1",
                    TOOL_RUN_COMMAND,
                    serde_json::json!({"cmd": "df -h", "explain": "看磁盘", "side_effect": "无"}),
                )]),
                resp_final("磁盘 91%"),
            ],
            rt.clone(),
        );
        eng.cfg.auto_run_readonly = true;
        let out = eng.ask(&ctx(), None).await.unwrap();
        assert_eq!(out.proposed[0].disposition, Disposition::Executed);
        assert_eq!(rt.run_log.lock().unwrap()[0], "df -h");
    }

    #[tokio::test]
    async fn read_remote_file_tool_works() {
        let rt = Arc::new(MockRuntime::default());
        rt.files
            .lock()
            .unwrap()
            .push(("/var/log/nginx/error.log".into(), "EACCES denied".into()));
        rt.approved.store(true, std::sync::atomic::Ordering::SeqCst);
        let eng = engine(
            vec![
                resp_with_tools(vec![tool_call(
                    "t1",
                    TOOL_READ_REMOTE_FILE,
                    serde_json::json!({"path": "/var/log/nginx/error.log"}),
                )]),
                resp_final("nginx 报权限错误"),
            ],
            rt.clone(),
        );
        let out = eng.ask(&ctx(), None).await.unwrap();
        assert_eq!(out.text, "nginx 报权限错误");
        assert!(out.tool_log.iter().any(|t| t.tool == TOOL_READ_REMOTE_FILE));
    }

    #[tokio::test]
    async fn redaction_map_restores_proposed_command() {
        let rt = Arc::new(MockRuntime::default());
        rt.approved.store(true, std::sync::atomic::Ordering::SeqCst);
        let eng = engine(
            vec![
                // LLM 看到的上下文里 IP 已被脱敏，它「学会」用占位符回代理命令
                resp_with_tools(vec![tool_call(
                    "t1",
                    TOOL_RUN_COMMAND,
                    serde_json::json!({"cmd": "curl -s http://<INTERNAL_IP_1>/api/health", "explain": "探测", "side_effect": "无"}),
                )]),
                resp_final("建议直接探测 <INTERNAL_IP_1>"),
            ],
            rt.clone(),
        );
        let out = eng.ask(&ctx(), None).await.unwrap();
        // 输入含 10.0.0.5 → 占位符 <INTERNAL_IP_1>；LLM 回的占位符必须还原
        assert_eq!(
            rt.run_log.lock().unwrap()[0],
            "curl -s http://10.0.0.5/api/health"
        );
        assert_eq!(out.text, "建议直接探测 10.0.0.5");
    }

    #[tokio::test]
    async fn monitor_trigger_prepends_automatic_notice() {
        let rt = Arc::new(MockRuntime::default());
        rt.approved.store(true, std::sync::atomic::Ordering::SeqCst);
        let eng = engine(
            vec![resp_final("先看 top -bn1")],
            rt.clone(),
        );
        let mut c = ctx();
        c.question = String::new();
        c.trigger = Trigger::Monitor("CPU 99% 持续 30 秒".into());
        let out = eng.ask(&c, None).await.unwrap();
        assert_eq!(out.text, "先看 top -bn1");
        assert!(out.proposed.is_empty());
    }

    #[tokio::test]
    async fn unsupported_tool_returns_error_not_panic() {
        let rt = Arc::new(MockRuntime::default());
        rt.approved.store(true, std::sync::atomic::Ordering::SeqCst);
        let eng = engine(
            vec![
                resp_with_tools(vec![tool_call("t1", "match_file", serde_json::json!({}))]),
                resp_final("换个工具"),
            ],
            rt.clone(),
        );
        let out = eng.ask(&ctx(), None).await.unwrap();
        assert_eq!(out.text, "换个工具");
        assert!(out.tool_log.last().unwrap().is_error);
    }

    #[test]
    fn sentinel_wrap_posix_and_cmd() {
        assert_eq!(
            sentinel_wrap("df -h", ShellKind::Posix, "MSAI1"),
            "df -h; echo \"MSAI1:$?\""
        );
        // cmd.exe 形态不应包含 $?
        let cmd = sentinel_wrap("dir", ShellKind::Cmd, "MSAI1");
        assert!(cmd.contains("%errorlevel%"), "{cmd}");
    }
}

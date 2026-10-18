//! AI Copilot 抽屉：终端上下文采集 + Triage 编排 + Human-in-the-loop Run Gate。
//!
//! 这一层是 MeatShell 与 ai-copilot crate 之间唯一的粘合面：
//!
//! - 每个终端标签一份 [`TabAi`]，从会话输出流里抽取命令块（OSC 133 优先，
//!   MeatShell 自带的 OSC 697 shell hook 兜底），只保留最近 8KB 上下文；
//! - [`UiRuntime`] 实现 ai-copilot 的 `ToolRuntime`：把 AI 提议的命令写回
//!   **用户可见的 PTY**，退出码靠注入的 sentinel 回声抓取；
//! - Run Gate 的三档裁决决定命令是「回车执行」还是「仅填入终端」。
//!   没有任何后台静默执行路径 —— 所有副作用都在看得见的终端里发生。

use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ai_copilot::blocks::{strip_ansi, BlockParser, CommandBlock, ContextWindow, DEFAULT_CONTEXT_BYTES};
use ai_copilot::llm::ChatDelta;
use ai_copilot::risk::{Gate, RiskLevel};
use ai_copilot::shell::ShellKind;
use ai_copilot::triage::{
    sentinel_wrap, CommandOutcome, CopilotConfig, DiskUsage, Disposition, NetRate, ProposedCommand,
    SystemSnapshot as AiSnapshot, ToolRuntime, TriageContext, TriageEngine, Trigger,
};
use ai_copilot::{AppError, AppResult};
use async_trait::async_trait;
use chrono::Utc;
use slint::{ModelRc, VecModel};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;

use crate::app::panes::set_terminal_row;
use crate::config::Session;
use crate::resource::SystemSnapshot;
use crate::ssh::SessionCommand;
use crate::ui::{AiMessage, AppWindow};

/// Run Gate 等待用户裁决的上限。超时按「拒绝」处理，AI 侧会收到拒绝理由。
pub(super) const APPROVAL_TIMEOUT: Duration = Duration::from_secs(180);
/// 单条命令在 PTY 里的等待上限。
pub(super) const EXEC_TIMEOUT: Duration = Duration::from_secs(30);
/// 送进 prompt 的最大命令块数量（8KB 预算内，够用且便宜）。
pub(super) const MAX_CONTEXT_BLOCKS: usize = 8;
/// 注入 PTY 的 sentinel marker 前缀；带它的命令不进 AI 上下文。
pub(super) const AI_SENTINEL_PREFIX: &str = "__msai_";

// ─── 每标签的 AI 上下文 ────────────────────────────────────────────

/// 一次带 sentinel 的命令执行捕获。
struct ExecCapture {
    marker: String,
    output: String,
    exit: Option<i32>,
    done: bool,
}

impl ExecCapture {
    /// 在已归一化的文本里寻找 sentinel 行 `<marker>:<exit>`。
    fn feed(&mut self, clean: &str) {
        let mut work = clean.to_string();
        if let Some(pos) = work.find(&self.marker) {
            let marker_end = pos + self.marker.len();
            let tail = &work[marker_end..];
            self.exit = tail
                .trim_start_matches(':')
                .lines()
                .next()
                .and_then(|l| l.trim().parse::<i32>().ok());
            // 丢掉 sentinel 行本身：它不是用户该看到的输出。
            let keep = tail
                .find('\n')
                .map(|i| marker_end + i + 1)
                .unwrap_or(work.len());
            let after = work[keep.min(work.len())..].to_string();
            work.truncate(pos);
            work.push_str(&after);
            self.done = true;
        }
        self.output.push_str(&work);
    }
}

pub(crate) struct TabAi {
    parser: BlockParser,
    blocks: ContextWindow,
    /// 自上一个块边界以来累积的输出（OSC 697 兜底路径才会用到）。
    hook_out: String,
    /// 见到过 OSC 133 就永远走语义块解析，不再用 hook 兜底（避免双计数）。
    saw_osc133: bool,
    exec: Option<ExecCapture>,
    /// 引擎正在等待的用户裁决：卡片 id → 回复通道。
    approval: Option<(String, oneshot::Sender<bool>)>,
    /// 抽屉内容的权威副本；Slint 模型只是它的镜像。
    messages: Vec<AiMessage>,
    busy: bool,
    /// 每次「清空 / 停止」自增：还在跑的旧 ask() 会看到 generation 变了，
    /// 于是放弃自己的 UI 写入，避免已取消的回复覆盖新会话。
    generation: u64,
}

pub(crate) type AiTabHandle = Arc<Mutex<TabAi>>;

impl TabAi {
    pub(crate) fn new() -> Self {
        Self {
            parser: BlockParser::new(),
            blocks: ContextWindow::new(DEFAULT_CONTEXT_BYTES),
            hook_out: String::new(),
            saw_osc133: false,
            exec: None,
            approval: None,
            messages: Vec::new(),
            busy: false,
            generation: 0,
        }
    }

    /// 喂一段 PTY 输出（会话层已解码为文本）。由会话 pump 线程调用。
    pub(super) fn feed_output(&mut self, text: &str) {
        if !self.saw_osc133 && text.contains("]133;") {
            self.saw_osc133 = true;
        }
        for block in self.parser.feed(text) {
            self.blocks.push(block);
        }
        let clean = normalize_newlines(&strip_ansi(text));
        if clean.is_empty() {
            return;
        }
        if !self.saw_osc133 {
            self.hook_out.push_str(&clean);
        }
        if let Some(exec) = self.exec.as_mut() {
            exec.feed(&clean);
        }
    }

    /// MeatShell shell hook 捕获到一条执行过的命令（`SessionEvent::CommandRan`）。
    ///
    /// OSC 697 是在 precmd 里发出的，也就是**这条命令的输出已经打完之后**，
    /// 因此此刻累积的输出正属于 `cmd` 本身（不是上一条）。自己注入的 sentinel
    /// 命令不进上下文 —— 否则 AI 会看到一堆 `__msai_xxx:$?`。
    pub(super) fn note_command(&mut self, cmd: &str) {
        if self.saw_osc133 || cmd.trim().is_empty() || cmd.contains(AI_SENTINEL_PREFIX) {
            return;
        }
        let out = strip_echo(std::mem::take(&mut self.hook_out), cmd);
        let now = Utc::now();
        self.blocks.push(CommandBlock {
            command: cmd.trim().to_string(),
            output: out.trim_end().to_string(),
            exit_code: None,
            started_at: now,
            finished_at: Some(now),
            cwd: None,
            finished: true,
        });
    }

    /// 最近若干条命令块（最早 → 最新）。
    pub(super) fn context_blocks(&self, limit: usize) -> Vec<CommandBlock> {
        let all = self.blocks.blocks();
        all.iter().skip(all.len().saturating_sub(limit)).cloned().collect()
    }

    /// 登记一次等待用户裁决的卡片。
    pub(super) fn set_approval(&mut self, id: String, tx: oneshot::Sender<bool>) {
        // 上一张卡还没回应就又来一张 —— 直接按拒绝结算，引擎不会卡死。
        if let Some((_, prev)) = self.approval.take() {
            let _ = prev.send(false);
        }
        self.approval = Some((id, tx));
    }

    /// 用户在抽屉里点了「执行 / 填入 / 拒绝」。返回是否真的回应了某张卡。
    pub(super) fn answer_approval(&mut self, id: &str, ok: bool) -> bool {
        match self.approval.take() {
            Some((cur, tx)) if cur == id => {
                let _ = tx.send(ok);
                true
            }
            other => {
                self.approval = other;
                false
            }
        }
    }

    /// Run Gate 第 4 道墙：开始监听一次带 sentinel 的执行。
    pub(super) fn arm_exec(&mut self, marker: &str) {
        self.exec = Some(ExecCapture {
            marker: marker.to_string(),
            output: String::new(),
            exit: None,
            done: false,
        });
    }

    /// 取出已完成（sentinel 已出现）的执行结果；没完成就保留监听状态。
    pub(super) fn take_finished_exec(&mut self) -> Option<(String, Option<i32>)> {
        let done = self.exec.as_ref().map(|e| e.done).unwrap_or(false);
        if !done {
            return None;
        }
        self.exec.take().map(|e| (e.output, e.exit))
    }

    /// 放弃监听（超时 / 会话断开）。
    pub(super) fn clear_exec(&mut self) {
        self.exec = None;
    }

    pub(super) fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
    }

    pub(super) fn is_busy(&self) -> bool {
        self.busy
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    /// 「停止 / 清空」：作废当前轮次，回收等待中的审批。
    pub(super) fn cancel_generation(&mut self) -> u64 {
        if let Some((_, tx)) = self.approval.take() {
            let _ = tx.send(false);
        }
        self.exec = None;
        self.busy = false;
        self.generation += 1;
        self.generation
    }

    /// 清空对话记录（generation 递增，令在飞的回复自行丢弃）。
    pub(super) fn clear_messages(&mut self) -> Vec<AiMessage> {
        self.messages.clear();
        Vec::new()
    }
}

/// PTY 走 CRLF；送给 LLM 之前统一成 LF，省下一批毫无信息量的回车。
fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n")
}

/// 去掉 PTY 回显的命令本身，只留下它的输出。
fn strip_echo(out: String, cmd: &str) -> String {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return out;
    }
    let Some(pos) = out.find(cmd) else {
        return out;
    };
    if !out[..pos].chars().all(|c| matches!(c, '\r' | '\n' | ' ' | '\0')) {
        return out;
    }
    out[pos + cmd.len()..].trim_start_matches(['\r', '\n']).to_string()
}

// ─── 抽屉内容的 Slint 镜像 ────────────────────────────────────────

/// 把一份消息副本刷进 Slint。UI 线程可能正忙，因此统一走事件循环。
fn sync_messages(weak: &slint::Weak<AppWindow>, tab_id: &str, rows: Vec<AiMessage>) {
    let weak = weak.clone();
    let tab_id = tab_id.to_string();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(win) = weak.upgrade() else {
            return;
        };
        set_terminal_row(&win, &tab_id, |row| {
            row.ai_messages = ModelRc::from(Rc::new(VecModel::from(rows.clone())));
        });
    });
}

/// 抽屉忙碌状态同步到 Slint（行存在才生效）。
fn sync_busy(weak: &slint::Weak<AppWindow>, tab_id: &str, busy: bool) {
    let weak = weak.clone();
    let tab_id = tab_id.to_string();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(win) = weak.upgrade() {
            set_terminal_row(&win, &tab_id, |row| row.ai_busy = busy);
        }
    });
}

/// 在 TabAi 的消息向量上做一次原子修改，并把结果镜像给 Slint。
///
/// `generation` 为 None 表示无条件写入（UI 侧操作）；否则只在 generations
/// 匹配时写入 —— 用户点了「停止」之后，在飞的那次 ask() 就再也不会改动抽屉。
fn with_messages(
    ai: &AiTabHandle,
    weak: &slint::Weak<AppWindow>,
    tab_id: &str,
    generation: Option<u64>,
    f: impl FnOnce(&mut Vec<AiMessage>),
) {
    let rows = {
        let mut guard = ai.lock().unwrap_or_else(|e| e.into_inner());
        if generation.is_some_and(|g| g != guard.generation()) {
            return;
        }
        f(&mut guard.messages);
        guard.messages.clone()
    };
    sync_messages(weak, tab_id, rows);
}

fn risk_tag(r: RiskLevel) -> &'static str {
    match r {
        RiskLevel::ReadOnly => "read-only",
        RiskLevel::Mutating => "mutating",
        RiskLevel::Destructive => "destructive",
    }
}

fn gate_tag(g: Gate) -> &'static str {
    match g {
        Gate::DirectRun => "direct",
        Gate::FillTerminal => "fill",
        Gate::Blocked => "blocked",
    }
}

fn disposition_tag(d: Disposition) -> &'static str {
    match d {
        Disposition::Pending => "pending",
        Disposition::Executed => "executed",
        Disposition::FilledForManualRun => "filled",
        Disposition::Rejected => "rejected",
        Disposition::Blocked => "blocked",
    }
}

/// 已存在同 id 的卡片就更新（ disposition 会随执行结果变化），否则追加。
fn upsert_card(rows: &mut Vec<AiMessage>, card: AiMessage) {
    if let Some(row) = rows
        .iter_mut()
        .find(|m| !m.card_id.is_empty() && m.card_id == card.card_id)
    {
        *row = card;
    } else {
        rows.push(card);
    }
}

pub(super) fn message_card(p: &ProposedCommand) -> AiMessage {
    AiMessage {
        role: ROLE_CARD,
        text: String::new().into(),
        card_id: p.id.clone().into(),
        cmd: p.cmd.clone().into(),
        explain: p.explain.clone().into(),
        side_effect: p.side_effect.clone().into(),
        risk: risk_tag(p.risk).into(),
        gate: gate_tag(p.gate).into(),
        disposition: disposition_tag(p.disposition).into(),
        blocked_reason: p.blocked_reason.clone().unwrap_or_default().into(),
    }
}

/// AiMessage.role 取值：用户 / 助手 / 命令卡片 / 错误。
pub(super) const ROLE_USER: i32 = 0;
pub(super) const ROLE_ASSISTANT: i32 = 1;
pub(super) const ROLE_CARD: i32 = 2;
pub(super) const ROLE_ERROR: i32 = 3;

/// 抽屉里追加一条纯文本消息（摘要 / 错误提示）。
pub(super) fn push_notice(
    ai: &AiTabHandle,
    weak: &slint::Weak<AppWindow>,
    tab_id: &str,
    role: i32,
    text: &str,
) {
    let msg = AiMessage {
        role,
        text: text.to_string().into(),
        ..Default::default()
    };
    with_messages(ai, weak, tab_id, None, |v| v.push(msg));
}

pub(super) fn clear_conversation(
    ai: &AiTabHandle,
    weak: &slint::Weak<AppWindow>,
    tab_id: &str,
) {
    let rows = ai
        .lock()
        .map(|mut g| {
            g.cancel_generation();
            g.clear_messages()
        })
        .unwrap_or_default();
    sync_messages(weak, tab_id, rows);
}

/// 抽屉里是否已有对话（决定是否自动发起一轮监控触发的诊断）。
pub(super) fn has_messages(ai: &AiTabHandle) -> bool {
    ai.lock().map(|g| !g.messages.is_empty()).unwrap_or(false)
}

/// 作废当前轮次：结清等待中的审批并让在飞的 ask() 放弃 UI 写入。
pub(super) fn cancel_generation(ai: &AiTabHandle) -> u64 {
    match ai.lock() {
        Ok(mut g) => g.cancel_generation(),
        Err(e) => e.into_inner().cancel_generation(),
    }
}

/// 某张卡片的 gate 与命令：UI 据此决定「批准执行」还是「仅填入终端」。
pub(super) fn card_info(ai: &AiTabHandle, card_id: &str) -> Option<(String, String)> {
    let guard = ai.lock().ok()?;
    guard
        .messages
        .iter()
        .find(|m| m.card_id == card_id)
        .map(|m| (m.gate.to_string(), m.cmd.to_string()))
}

pub(super) fn answer_approval(ai: &AiTabHandle, card_id: &str, ok: bool) -> bool {
    match ai.lock() {
        Ok(mut g) => g.answer_approval(card_id, ok),
        Err(e) => e.into_inner().answer_approval(card_id, ok),
    }
}

pub(super) fn is_busy(ai: &AiTabHandle) -> bool {
    ai.lock().map(|g| g.is_busy()).unwrap_or(false)
}

/// 通过 tab 的投递路由取到它的 AI 上下文句柄。
pub(super) fn ai_handle(core: &crate::app::AppCore, tab_id: &str) -> Option<AiTabHandle> {
    let routes = core.tab_routes.lock().ok()?;
    let route = routes.get(tab_id)?.clone();
    route.lock().ok().map(|g| g.ai.clone())
}

/// 页面/窗口换了之后，把 Rust 侧持有的对话重刷进新的 Slint 模型。
pub(super) fn resync_conversation(
    core: &crate::app::AppCore,
    weak: &slint::Weak<AppWindow>,
    tab_id: &str,
) {
    let Some(ai) = ai_handle(core, tab_id) else {
        return;
    };
    let rows = ai.lock().map(|g| g.messages.clone()).unwrap_or_default();
    sync_messages(weak, tab_id, rows);
}

// ─── ToolRuntime：AI 唯一的副作用出口 ─────────────────────────────

pub(super) struct UiRuntime {
    tab_id: String,
    ai: AiTabHandle,
    weak: slint::Weak<AppWindow>,
    /// PTY 写通道。None = 这个标签没有可写入的终端（AI 只能聊天）。
    raw: Option<UnboundedSender<SessionCommand>>,
    /// 本次 ask() 的世代号；抽屉被清空 / 停止后其 UI 写入自动作废。
    generation: u64,
    /// 标签对应的会话定义（可能缺失：本地/串口标签没有 SSH 会话）。
    session: Option<Session>,
    jump: Vec<Session>,
    shell: ShellKind,
}

impl UiRuntime {
    /// 把一行文本写进 PTY —— 始终是用户看得见的那个终端。
    fn send_line(&self, line: &str) -> AppResult<()> {
        let mut bytes = line.as_bytes().to_vec();
        bytes.push(b'\n');
        let raw = self.raw.as_ref().ok_or_else(|| {
            AppError::pty("no_live_terminal", serde_json::json!({}))
        })?;
        raw.send(SessionCommand::RawInput(bytes))
            .map_err(|_| AppError::pty("session_channel_closed", serde_json::json!({})))
    }
}

#[async_trait]
impl ToolRuntime for UiRuntime {
    async fn request_approval(&self, p: &ProposedCommand) -> AppResult<bool> {
        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.ai.lock().unwrap_or_else(|e| e.into_inner());
            guard.set_approval(p.id.clone(), tx);
        }
        let card = message_card(p);
        with_messages(&self.ai, &self.weak, &self.tab_id, Some(self.generation), |v| {
            upsert_card(v, card)
        });
        match tokio::time::timeout(APPROVAL_TIMEOUT, rx).await {
            Ok(Ok(ok)) => Ok(ok),
            // 通道关闭（抽屉/会话已关）与超时的处置一致：按拒绝处理，
            // AI 侧会收到拒绝并调整策略，用户的终端不会有任何动静。
            Ok(Err(_)) | Err(_) => Ok(false),
        }
    }

    async fn execute_approved(&self, p: &ProposedCommand) -> AppResult<CommandOutcome> {
        let marker = format!("{}{}", AI_SENTINEL_PREFIX, uuid::Uuid::new_v4().simple());
        let line = sentinel_wrap(&p.cmd, self.shell, &marker);
        {
            let mut guard = self.ai.lock().unwrap_or_else(|e| e.into_inner());
            guard.arm_exec(&marker);
        }
        self.send_line(&line)?;
        let deadline = tokio::time::Instant::now() + EXEC_TIMEOUT;
        loop {
            tokio::time::sleep(Duration::from_millis(80)).await;
            let finished = {
                self.ai
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take_finished_exec()
            };
            if let Some((output, exit_code)) = finished {
                return Ok(CommandOutcome {
                    exit_code,
                    output,
                    timed_out: false,
                });
            }
            if tokio::time::Instant::now() >= deadline {
                let mut guard = self.ai.lock().unwrap_or_else(|e| e.into_inner());
                guard.clear_exec();
                let partial = String::new();
                return Ok(CommandOutcome {
                    exit_code: None,
                    output: partial,
                    timed_out: true,
                });
            }
        }
    }

    async fn read_remote_file(&self, path: &str, max_bytes: usize) -> AppResult<String> {
        let Some(session) = self.session.clone() else {
            return Err(AppError::other(
                "no_session_for_remote_read",
                serde_json::json!({"path": path}),
            ));
        };
        let value = crate::automation::read_text(
            session,
            self.jump.clone(),
            path.to_string(),
            Duration::from_secs(20),
        )
        .await
        .map_err(|e| {
            AppError::other(
                "read_remote_file",
                serde_json::json!({"path": path, "error": e.to_string()}),
            )
        })?;
        let content = value
            .get("content")
            .and_then(|c| c.as_str())
            .unwrap_or_default();
        Ok(content.chars().take(max_bytes).collect())
    }
}

// ─── 一次 Triage ─────────────────────────────────────────────────

pub(super) struct AskParams {
    pub tab_id: String,
    pub question: String,
    pub trigger: Trigger,
    pub ai: AiTabHandle,
    pub weak: slint::Weak<AppWindow>,
    /// PTY 写通道；没有就说明会话尚未连上（此时 Triage 仍然可以纯聊天）。
    pub raw: Option<UnboundedSender<SessionCommand>>,
    pub session: Option<Session>,
    pub jump: Vec<Session>,
    pub cfg: CopilotConfig,
    pub shell: ShellKind,
    /// MeatShell 资源监控侧栏的同源快照。
    pub local: Option<SystemSnapshot>,
}

/// 发起一轮 AI 诊断。返回后立即回到 UI：所有网络 / 工具执行都在 tokio 侧。
pub(super) fn spawn_ask(runtime: &tokio::runtime::Handle, params: AskParams) {
    let AskParams {
        tab_id,
        question,
        trigger,
        ai,
        weak,
        raw,
        session,
        jump,
        cfg,
        shell,
        local,
    } = params;

    // 先把用户提问与一条空的助手占位行压进抽屉，拿到流式更新的目标下标。
    let mut stream_index = 0usize;
    with_messages(&ai, &weak, &tab_id, None, |v| {
        v.push(AiMessage {
            role: ROLE_USER,
            text: question.clone().into(),
            ..Default::default()
        });
        v.push(AiMessage {
            role: ROLE_ASSISTANT,
            ..Default::default()
        });
        stream_index = v.len() - 1;
    });

    let generation = ai
        .lock()
        .map(|g| g.generation())
        .unwrap_or_default();
    let backend = Arc::new(UiRuntime {
        tab_id: tab_id.clone(),
        ai: ai.clone(),
        weak: weak.clone(),
        raw,
        generation,
        session,
        jump,
        shell,
    });
    let engine = match TriageEngine::new(cfg.clone(), backend) {
        Ok(e) => e,
        Err(e) => {
            push_notice(
                &ai,
                &weak,
                &tab_id,
                ROLE_ERROR,
                &format!("{e}"),
            );
            return;
        }
    };

    let blocks = ai
        .lock()
        .map(|g| g.context_blocks(MAX_CONTEXT_BLOCKS))
        .unwrap_or_default();
    let ctx = TriageContext {
        question,
        blocks,
        system: local.as_ref().map(to_ai_snapshot),
        shell,
        trigger,
    };

    let sink: ai_copilot::DeltaSink = Arc::new({
        let ai = ai.clone();
        let weak = weak.clone();
        let tab_id = tab_id.clone();
        move |delta| {
            if let ChatDelta::Text(text) = delta {
                with_messages(&ai, &weak, &tab_id, Some(generation), |v| {
                    if let Some(row) = v.get_mut(stream_index) {
                        row.text = format!("{}{}", row.text, text).into();
                        row.role = ROLE_ASSISTANT;
                    }
                });
            }
        }
    });

    if let Ok(mut guard) = ai.lock() {
        guard.set_busy(true);
    }
    sync_busy(&weak, &tab_id, true);
    runtime.spawn(async move {
        let result = engine.ask(&ctx, Some(sink)).await;
        with_messages(&ai, &weak, &tab_id, Some(generation), |v| match result {
            Ok(outcome) => {
                // 最终结论覆盖流式拼接结果（模型可能重发整段）。
                if let Some(row) = v.get_mut(stream_index) {
                    row.text = outcome.text.clone().into();
                    row.role = ROLE_ASSISTANT;
                }
                for proposal in &outcome.proposed {
                    upsert_card(v, message_card(proposal));
                }
            }
            Err(e) => {
                if let Some(row) = v.get_mut(stream_index) {
                    row.text = format!("{e}").into();
                    row.role = ROLE_ERROR;
                }
            }
        });
        let clear_busy = {
            let mut guard = ai.lock().unwrap_or_else(|e| e.into_inner());
            if guard.generation() == generation {
                guard.set_busy(false);
            }
            guard.generation() == generation
        };
        if clear_busy {
            sync_busy(&weak, &tab_id, false);
        }
    });
}

#[cfg(test)]
#[path = "../../tests/app/ai_copilot/mod.rs"]
mod ai_copilot_tests;

/// MeatShell 本地监控快照 → AI 侧快照（同一批 CPU/内存/磁盘/网络数据）。
fn to_ai_snapshot(s: &SystemSnapshot) -> AiSnapshot {
    const MIB: u64 = 1024 * 1024;
    AiSnapshot {
        cpu_usage_pct: s.cpu_percent,
        mem_used_bytes: s.mem_used_mib * MIB,
        mem_total_bytes: s.mem_total_mib * MIB,
        swap_used_bytes: s.swap_used_mib * MIB,
        swap_total_bytes: s.swap_total_mib * MIB,
        load_avg: [0.0, 0.0, 0.0],
        disks: s
            .disks
            .iter()
            .map(|(mount, available, total)| DiskUsage {
                mount: mount.clone(),
                used_bytes: total.saturating_sub(*available),
                total_bytes: *total,
            })
            .collect(),
        nets: vec![NetRate {
            iface: "total".into(),
            rx_bytes_per_s: s.net_rx_per_sec,
            tx_bytes_per_s: s.net_tx_per_sec,
        }],
        // 本地视图只有整机指标；进程级快照让 AI 自己用 ps 去取更有价值。
        top_processes: Vec::new(),
        sampled_at: Some(Utc::now()),
    }
}

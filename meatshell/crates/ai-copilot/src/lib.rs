//! ai-copilot —— MeatShell × rssh 缝合的「AI 运维 Copilot」核心 crate。
//!
//! 组成：
//! - `sanitize` / `risk` / `shell` / `llm` / `tools`：从 [rssh](https://github.com/shihuili1218/rssh)
//!   移植的便携 Rust 逻辑（tree-sitter 命令形状校验、49 条黑名单、sentinel
//!   模板、SSE 流式 LLM 客户端），API 与上游保持兼容。
//! - `blocks`：**新增** —— OSC 133 语义命令块解析 + 8KB 上下文环形缓冲，
//!   补上 rssh 前端 xterm 侧块划分的 Rust 对应物，让 MeatShell 的只读 VT
//!   终端也能精准界定「命令 / 输出 / 退出码」。
//! - `redact`：**增强** —— rssh 单向脱敏（`<REDACTED:ip-10>`）之上增加
//!   编号占位符 + 本地反向还原映射，AI 回代的命令可以安全还原后注入 PTY。
//! - `risk` / `triage`：**新增** —— 三档风险分级（ReadOnly / Mutating /
//!   Destructive）、Run Gate 执行网关、以及融合 MeatShell 硬件监控快照的
//!   Triage 引擎（含 Human-in-the-Loop 审批循环）。
//! - `audit`：从 rssh 移植的内存审计日志。
//!
//! 引擎不持有任何 SSH/PTY 句柄：所有副作用经由 `triage::ToolRuntime` trait
//! 由宿主（MeatShell）实现，单测可全链路 Mock。

pub mod audit;
pub mod blocks;
pub mod error;
pub mod llm;
pub mod redact;
pub mod risk;
pub mod sanitize;
pub mod shell;
pub mod tools;
pub mod triage;

pub use error::{AppError, AppResult};
pub use llm::{
    build_client, protocol_valid, ChatDelta, ChatMessage, ChatRequest, ChatResponse, DeltaSink,
    LlmClient, ModelInfo, Protocol, ToolCall, ToolSchema,
};
pub use sanitize::{validate_with, Blacklist, ShapeError, DEFAULT_MAX_OUTPUT_BYTES};

pub use blocks::{BlockParser, CommandBlock, ContextWindow, DEFAULT_CONTEXT_BYTES};
pub use redact::{
    builtin_rule_specs, validate_pattern, IndexedRedactor, RedactionMap, RedactRuleSpec,
};
pub use risk::{assess_command, gate_of, Gate, RiskAssessment, RiskLevel};
pub use triage::{
    CopilotConfig, CommandOutcome, DiskUsage, Disposition, NetRate, ProcInfo, ProposedCommand,
    SystemSnapshot, ToolRuntime, TriageContext, TriageEngine, TriageOutcome, Trigger,
    TOOL_READ_REMOTE_FILE,
};

//! ai-copilot 的错误类型。
//!
//! API 有意与 rssh 的 `crate::error` 保持兼容（`AppError::other/config/...`、
//! `code()`、`error_chain`、`From<io::Error>`），这样从 rssh 移植过来的
//! `sanitize` / `llm` / `redaction` 代码可以原样工作，无需改动 import。
//! 区别仅在于去掉了 Tauri 前端的 i18n 协议串（`__rssh_err__|{...}`）。

use std::fmt;

use serde_json::json;

/// 带稳定 code + 结构化参数的错误消息。
#[derive(Debug, Clone)]
pub struct CodedMsg {
    pub code: &'static str,
    pub params: serde_json::Value,
}

impl CodedMsg {
    pub fn new(code: &'static str, params: serde_json::Value) -> Self {
        Self { code, params }
    }
}

impl fmt::Display for CodedMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.params)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Ssh(CodedMsg),
    #[error("{0}")]
    Sftp(CodedMsg),
    #[error("{0}")]
    Pty(CodedMsg),
    #[error("{0}")]
    NotFound(CodedMsg),
    #[error("{0}")]
    Config(CodedMsg),
    #[error("{0}")]
    Other(CodedMsg),
    #[error("{0}")]
    Io(CodedMsg),
    #[error("{0}")]
    Database(CodedMsg),
    /// 锁中毒——编程 bug，固定 code，无参数。
    #[error("[lock_poisoned] {{}}")]
    Lock,
}

impl AppError {
    pub fn ssh(code: &'static str, params: serde_json::Value) -> Self {
        Self::Ssh(CodedMsg::new(code, params))
    }
    pub fn sftp(code: &'static str, params: serde_json::Value) -> Self {
        Self::Sftp(CodedMsg::new(code, params))
    }
    pub fn pty(code: &'static str, params: serde_json::Value) -> Self {
        Self::Pty(CodedMsg::new(code, params))
    }
    pub fn not_found(code: &'static str, params: serde_json::Value) -> Self {
        Self::NotFound(CodedMsg::new(code, params))
    }
    pub fn config(code: &'static str, params: serde_json::Value) -> Self {
        Self::Config(CodedMsg::new(code, params))
    }
    pub fn other(code: &'static str, params: serde_json::Value) -> Self {
        Self::Other(CodedMsg::new(code, params))
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Ssh(m) | Self::Sftp(m) | Self::Pty(m) | Self::NotFound(m) | Self::Config(m)
            | Self::Other(m) | Self::Io(m) | Self::Database(m) => m.code,
            Self::Lock => "lock_poisoned",
        }
    }

    pub fn params(&self) -> &serde_json::Value {
        static EMPTY: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
        match self {
            Self::Ssh(m) | Self::Sftp(m) | Self::Pty(m) | Self::NotFound(m) | Self::Config(m)
            | Self::Other(m) | Self::Io(m) | Self::Database(m) => &m.params,
            Self::Lock => EMPTY.get_or_init(|| json!({})),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(CodedMsg::new(
            "io_error",
            json!({ "err": e.to_string() }),
        ))
    }
}

/// 打印整条错误链，用于 LLM 请求失败等场景的诊断信息。
pub fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut msg = err.to_string();
    let mut src = err.source();
    while let Some(s) = src {
        msg.push_str(" <- ");
        msg.push_str(&s.to_string());
        src = s.source();
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coded_variants_expose_code() {
        assert_eq!(AppError::config("bad", json!({})).code(), "bad");
        assert_eq!(AppError::other("oops", json!({})).code(), "oops");
        assert_eq!(AppError::Lock.code(), "lock_poisoned");
        let io: AppError = std::io::Error::other("boom").into();
        assert_eq!(io.code(), "io_error");
    }

    #[test]
    fn error_chain_includes_source() {
        #[derive(Debug, thiserror::Error)]
        #[error("outer")]
        struct Outer(#[source] Inner);
        #[derive(Debug, thiserror::Error)]
        #[error("inner")]
        struct Inner;
        let e = Outer(Inner);
        assert_eq!(error_chain(&e), "outer <- inner");
    }
}

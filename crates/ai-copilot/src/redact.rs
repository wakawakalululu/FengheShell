//! 本地隐私脱敏：编号占位符 + 反向还原映射。
//!
//! rssh 的脱敏是单向的（`<REDACTED:ip-10>` 字面替换，`NoExpand` 防 `$1`
//! 注入）。这带来一个体验缺口：AI 返回的建议命令里带着占位符，用户无法
//! 直接拿去执行。本模块在 rssh 语义之上补上「映射表 + 反向还原」：
//!
//! - 出站（本地 → LLM）：正则命中 → 编号占位符 `<INTERNAL_IP_1>`，
//!   同时把 `占位符 → 原文` 记入 `RedactionMap`（只留在本地内存）。
//! - 回站（LLM → 本地）：`RedactionMap::restore` 在前端渲染 / PTY 注入前
//!   把占位符还原为真实值。
//!
//! 规则集与 rssh `db::schema` v13 seed 的 8 条内置规则一致（IP × 3 /
//! bearer / sk-key / aws-key / jwt / hex），用户自定义规则经
//! `validate_pattern` 校验（必须可编译且非零宽匹配）。

use std::collections::HashMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use serde_json::json;

/// 用户可见的脱敏规则声明（持久化形态）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedactRuleSpec {
    pub id: String,
    /// 占位符标签，如 `INTERNAL_IP` / `TOKEN` / `API_KEY` / `HEX`。
    pub label: String,
    pub pattern: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// rssh db::schema v13 seed 的同款 8 条内置规则（in-code 镜像）。
pub fn builtin_rule_specs() -> Vec<RedactRuleSpec> {
    [
        ("ip-10", "INTERNAL_IP", r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        (
            "ip-172",
            "INTERNAL_IP",
            r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
        ),
        ("ip-192", "INTERNAL_IP", r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
        ("bearer", "TOKEN", r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),
        ("sk-key", "API_KEY", r"\bsk-[A-Za-z0-9]{20,}\b"),
        ("aws-key", "AWS_KEY", r"\bAKIA[0-9A-Z]{16}\b"),
        (
            "jwt",
            "TOKEN",
            r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        ),
        ("hex", "HEX", r"\b[0-9a-fA-F]{32,}\b"),
    ]
    .into_iter()
    .map(|(id, label, pattern)| RedactRuleSpec {
        id: id.to_string(),
        label: label.to_string(),
        pattern: pattern.to_string(),
        enabled: true,
    })
    .collect()
}

struct CompiledRule {
    id: String,
    label: String,
    regex: Regex,
}

/// 编号脱敏器：`apply` 产出带编号占位符的文本 + 还原映射。
pub struct IndexedRedactor {
    rules: Vec<CompiledRule>,
}

impl std::fmt::Debug for IndexedRedactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexedRedactor")
            .field(
                "rules",
                &self.rules.iter().map(|r| &r.id).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl IndexedRedactor {
    /// 从用户规则集构造（含校验：可编译 + 非零宽）。
    pub fn from_specs(specs: &[RedactRuleSpec]) -> AppResult<Self> {
        let mut rules = Vec::new();
        for spec in specs {
            if !spec.enabled {
                continue;
            }
            validate_pattern(&spec.pattern)?;
            rules.push(CompiledRule {
                id: spec.id.clone(),
                label: spec.label.clone(),
                regex: Regex::new(&spec.pattern).map_err(|e| {
                    AppError::config(
                        "redact_invalid_regex",
                        json!({ "pattern": spec.pattern, "error": e.to_string() }),
                    )
                })?,
            });
        }
        Ok(Self { rules })
    }

    /// 内置 8 条规则。
    pub fn builtin() -> Self {
        Self::from_specs(&builtin_rule_specs()).expect("builtin redaction rules must compile")
    }

    pub fn disabled() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 脱敏文本。命中处替换为 `<LABEL_n>` 编号占位符，映射写入 `map`。
    ///
    /// 相同原文（同标签下）始终得到同一占位符，保证 LLM 看到的是
    /// 「同一个内网 IP」而不是一堆孤立 token。
    pub fn apply(&self, text: &str, map: &mut RedactionMap) -> String {
        let mut out = text.to_string();
        for rule in &self.rules {
            // 逐条 replace_all；closure 的返回值即替换文本（字面量语义，
            // 天然免疫 `$1` 捕获组注入 —— rssh 用 NoExpand 解决的同一问题）。
            let regex = &rule.regex;
            let label = rule.label.as_str();
            let replaced: String = regex
                .replace_all(&out, |caps: &regex::Captures| {
                    let m = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
                    map.placeholder_for(label, m)
                })
                .into_owned();
            out = replaced;
        }
        out
    }
}

/// 占位符 → 原文 的本地还原映射（绝不外发）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RedactionMap {
    /// 占位符 → 原文。同一原文的重复命中共享同一占位符。
    entries: HashMap<String, String>,
    /// (label, 原文) → 占位符，保证同值同号。
    dedupe: HashMap<(String, String), String>,
    /// label → 已用最大编号。
    counters: HashMap<String, usize>,
}

impl RedactionMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn placeholder_for(&mut self, label: &str, original: &str) -> String {
        let key = (label.to_string(), original.to_string());
        if let Some(ph) = self.dedupe.get(&key) {
            return ph.clone();
        }
        let n = self.counters.entry(label.to_string()).or_insert(0);
        *n += 1;
        let ph = format!("<{label}_{n}>");
        self.entries.insert(ph.clone(), original.to_string());
        self.dedupe.insert(key, ph.clone());
        ph
    }

    pub fn insert(&mut self, placeholder: String, original: String) {
        self.entries.insert(placeholder, original);
    }

    /// 反向还原：先长后短替换，避免 `<TOKEN_1>` 撞 `<TOKEN_10>` 前缀。
    pub fn restore(&self, text: &str) -> String {
        if self.entries.is_empty() {
            return text.to_string();
        }
        let mut pairs: Vec<(&String, &String)> = self.entries.iter().collect();
        pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        let mut out = text.to_string();
        for (ph, orig) in pairs {
            out = out.replace(ph.as_str(), orig.as_str());
        }
        out
    }

    /// 已记录的 (占位符, 原文) 对数 —— UI 可展示「本次脱敏了 N 处」。
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// 校验用户自定义正则：必须可编译，且不能是零宽匹配（否则每个位置都会
/// 命中 → 灾难性全文替换）。移植自 rssh `redaction.rs`，错误码保持不变。
pub fn validate_pattern(pattern: &str) -> AppResult<()> {
    Regex::new(pattern).map_err(|e| {
        AppError::config(
            "redact_invalid_regex",
            json!({ "pattern": pattern, "error": e.to_string() }),
        )
    })?;
    if matches_empty(pattern) {
        return Err(AppError::config(
            "redact_zero_width_pattern",
            json!({ "pattern": pattern }),
        ));
    }
    Ok(())
}

fn matches_empty(pattern: &str) -> bool {
    regex_syntax::Parser::new()
        .parse(pattern)
        .map(|hir| hir.properties().minimum_len() == Some(0))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_redact_ips_tokens_keys() {
        let r = IndexedRedactor::builtin();
        let mut map = RedactionMap::new();
        let out = r.apply(
            "ssh 10.0.0.5 and 10.0.0.5 and 192.168.1.1 key sk-abcdefghijklmnopqrstuvwxyz012345",
            &mut map,
        );
        // 同一 IP 两次命中 → 同一编号
        assert_eq!(out.matches("<INTERNAL_IP_1>").count(), 2);
        assert_eq!(out.matches("<INTERNAL_IP_2>").count(), 1);
        assert!(out.contains("<API_KEY_1>"));
        assert!(!out.contains("10.0.0.5"));
        // 反向还原
        assert_eq!(
            map.restore("connect to <INTERNAL_IP_1>"),
            "connect to 10.0.0.5"
        );
        assert_eq!(
            map.restore("connect to <INTERNAL_IP_2>"),
            "connect to 192.168.1.1"
        );
    }

    #[test]
    fn bearer_and_jwt_and_aws() {
        let r = IndexedRedactor::builtin();
        let mut map = RedactionMap::new();
        let out = r.apply(
            "Authorization: Bearer abc.def-ghi_jkl token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123 aws AKIAIOSFODNN7EXAMPLE",
            &mut map,
        );
        assert!(!out.contains("Bearer abc"));
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(out.contains("<TOKEN_1>"));
    }

    #[test]
    fn replacement_is_literal_not_capture_template() {
        // rssh 用 NoExpand 解决的问题：占位符里出现 $1 不会被正则引擎展开。
        let specs = vec![RedactRuleSpec {
            id: "custom".into(),
            label: "SECRET".into(),
            pattern: r"(secret)-(\d+)".into(),
            enabled: true,
        }];
        let r = IndexedRedactor::from_specs(&specs).unwrap();
        let mut map = RedactionMap::new();
        let out = r.apply("value secret-42 end", &mut map);
        assert_eq!(out, "value <SECRET_1> end");
        assert_eq!(map.restore("<SECRET_1>"), "secret-42");
    }

    #[test]
    fn same_label_counter_is_shared_across_rules() {
        let r = IndexedRedactor::builtin();
        let mut map = RedactionMap::new();
        let out = r.apply("10.1.2.3 172.16.0.9 192.168.0.7", &mut map);
        // 三条 IP 规则共享 INTERNAL_IP 标签 → 编号连续
        assert!(out.contains("<INTERNAL_IP_1>"));
        assert!(out.contains("<INTERNAL_IP_2>"));
        assert!(out.contains("<INTERNAL_IP_3>"));
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn restore_prefers_longest_placeholder() {
        let mut map = RedactionMap::new();
        map.insert("<TOKEN_1>".into(), "a".into());
        map.insert("<TOKEN_10>".into(), "b".into());
        assert_eq!(map.restore("<TOKEN_10> and <TOKEN_1>"), "b and a");
    }

    #[test]
    fn rejects_invalid_and_zero_width_patterns() {
        assert_eq!(
            validate_pattern("(").unwrap_err().code(),
            "redact_invalid_regex"
        );
        for pattern in ["", "^", "$", "a*", r"\b", r"x*y*"] {
            assert_eq!(
                validate_pattern(pattern).unwrap_err().code(),
                "redact_zero_width_pattern"
            );
        }
        validate_pattern(r"secret-\d+").unwrap();
    }

    #[test]
    fn disabled_rules_are_skipped() {
        let specs = vec![RedactRuleSpec {
            id: "ip".into(),
            label: "IP".into(),
            pattern: r"\b10\.\d+\.\d+\.\d+\b".into(),
            enabled: false,
        }];
        let r = IndexedRedactor::from_specs(&specs).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn placeholder_roundtrip_is_stable_under_repeated_redaction() {
        let r = IndexedRedactor::builtin();
        let mut map = RedactionMap::new();
        let once = r.apply("host 10.0.0.9", &mut map);
        // 已脱敏文本再次脱敏不应改变（占位符不命中任何正则）
        let twice = r.apply(&once, &mut map);
        assert_eq!(once, twice);
    }
}

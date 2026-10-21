//! web_search：通过 Exa / Parallel 的匿名 Hosted MCP 做网络检索。
//!
//! 从 rssh `ai/web_search.rs` 移植，行为对齐上游：
//! - MCP 服务的文本响应**原样**返回给 LLM，不做结构化解析 —— Exa /
//!   Parallel 改响应形状时 rssh / FengheShell 都不会坏（与 opencode 同思路）。
//! - 唯一的本地处理是**查询发出前的本地脱敏**（网络出站边界）。
//! - 提供方由 routing_key 的哈希二选一（负载均衡），可用环境变量
//!   `FENGHESHELL_WEB_SEARCH_PROVIDER=exa|parallel` 强制指定。
//!
//! 与上游的差异仅限品牌：User-Agent 与错误文案里的 rssh → fengheshell
//! （与姊妹模块 `web_fetch` 保持同一 UA，见该模块）。

use std::fmt;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    sanitize::{self, RedactRule},
    tools::WebSearchInput,
};

const EXA_MCP_URL: &str = "https://mcp.exa.ai/mcp";
const PARALLEL_MCP_URL: &str = "https://search.parallel.ai/mcp";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(25);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const DEFAULT_RESULTS: usize = 8;
const MAX_RESULTS: usize = 20;
const MAX_QUERY_CHARS: usize = 512;
static HTTP_CLIENT: OnceLock<Result<reqwest::Client, ()>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebSearchProvider {
    Exa,
    Parallel,
}

impl WebSearchProvider {
    fn id(self) -> &'static str {
        match self {
            Self::Exa => "exa",
            Self::Parallel => "parallel",
        }
    }

    fn endpoint(self) -> &'static str {
        match self {
            Self::Exa => EXA_MCP_URL,
            Self::Parallel => PARALLEL_MCP_URL,
        }
    }
}

impl fmt::Display for WebSearchProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exa => formatter.write_str("Exa"),
            Self::Parallel => formatter.write_str("Parallel"),
        }
    }
}

#[derive(Debug, Clone)]
struct ValidatedQuery {
    query: String,
    limit: usize,
}

/// MCP 响应文本返回给 LLM 时不解析 —— 见模块文档。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSearchResponse {
    pub query: String,
    pub provider: String,
    pub text: String,
    pub elapsed_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum WebSearchError {
    #[error("{0}")]
    InvalidInput(&'static str),
    #[error("web_search could not initialize its HTTP client")]
    ClientBuild,
    #[error("web_search was rate-limited by {provider}; stop retrying and try again later")]
    RateLimited { provider: WebSearchProvider },
    #[error("web_search authentication was rejected by {provider}")]
    Authentication { provider: WebSearchProvider },
    #[error("web_search could not reach {provider}")]
    Unavailable { provider: WebSearchProvider },
    #[error("web_search received an invalid response from {provider}")]
    InvalidResponse { provider: WebSearchProvider },
    #[error("web_search response from {provider} exceeded the 256 KiB limit")]
    ResponseTooLarge { provider: WebSearchProvider },
}

/// 查询脱敏规则（单向 `<REDACTED:…>` 替换）：内网 IP / Token / 密钥等不出网。
/// 与 redact.rs 的内置 8 条规则同源，占位符命名与 rssh 的 DB seed 一致。
pub fn builtin_query_rules() -> Vec<RedactRule> {
    crate::redact::builtin_rule_specs()
        .into_iter()
        .map(|spec| {
            RedactRule::new(&spec.pattern, &format!("<REDACTED:{}>", spec.id))
                .expect("builtin redaction rules must compile")
        })
        .collect()
}

static SHARED_QUERY_RULES: OnceLock<Vec<RedactRule>> = OnceLock::new();

/// 进程内共享的查询脱敏规则（内置 8 条，只编译一次）。
///
/// 与引擎的 `IndexedRedactor` 分工：那个管「回传给 LLM 的内容」（编号占位符 +
/// 可还原），这个管「出网查询」的单向 `<REDACTED:…>` 替换 —— 语义对齐 rssh
/// （它的 web_search 用的就是 DB 里那套 RedactRule）。用户自定义脱敏规则暂不
/// 参与查询脱敏（内置 8 条已覆盖内网 IP / Token / 密钥），需要时再经引擎透传。
pub fn shared_query_rules() -> &'static [RedactRule] {
    SHARED_QUERY_RULES.get_or_init(builtin_query_rules)
}

fn build_query(
    input: &WebSearchInput,
    redact_rules: &[RedactRule],
) -> Result<ValidatedQuery, &'static str> {
    let raw_query = input.query.trim();
    if raw_query.is_empty() || raw_query.chars().count() > MAX_QUERY_CHARS {
        return Err("web_search query must be 1..=512 characters");
    }

    // This is the network egress boundary. Prompts can ask the model not to
    // copy secrets into a query, but only local redaction can enforce it.
    let redacted_query = sanitize::redact(raw_query, redact_rules);
    let query = redacted_query.trim();
    if query.is_empty() || query.chars().count() > MAX_QUERY_CHARS {
        return Err("web_search query must be 1..=512 characters");
    }

    let limit = input.max_results.unwrap_or(DEFAULT_RESULTS);
    if !(1..=MAX_RESULTS).contains(&limit) {
        return Err("web_search max_results must be between 1 and 20");
    }

    Ok(ValidatedQuery {
        query: query.to_owned(),
        limit,
    })
}

fn select_provider(routing_key: &str, provider_override: Option<&str>) -> WebSearchProvider {
    match provider_override {
        Some("exa") => return WebSearchProvider::Exa,
        Some("parallel") => return WebSearchProvider::Parallel,
        _ => {}
    }

    let hash = Sha256::digest(routing_key.as_bytes());
    if hash[0] % 2 == 0 {
        WebSearchProvider::Exa
    } else {
        WebSearchProvider::Parallel
    }
}

fn mcp_request(provider: WebSearchProvider, query: &ValidatedQuery) -> Value {
    let (name, arguments) = match provider {
        WebSearchProvider::Exa => (
            "web_search_exa",
            json!({
                "query": query.query,
                "type": "auto",
                "numResults": query.limit,
                "livecrawl": "fallback",
            }),
        ),
        WebSearchProvider::Parallel => (
            "web_search",
            json!({
                "objective": query.query,
                "search_queries": [query.query],
            }),
        ),
    };
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
        }
    })
}

#[derive(Debug, Deserialize)]
struct McpEnvelope {
    result: Option<McpResult>,
    error: Option<McpJsonError>,
}

#[derive(Debug, Deserialize)]
struct McpResult {
    #[serde(default)]
    content: Vec<McpContent>,
    #[serde(default, rename = "isError")]
    is_error: bool,
}

#[derive(Debug, Deserialize)]
struct McpContent {
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct McpJsonError {
    message: String,
}

struct McpText {
    text: String,
    is_error: bool,
}

fn parse_mcp_payload(payload: &str) -> Option<McpText> {
    let envelope: McpEnvelope = serde_json::from_str(payload.trim()).ok()?;
    if let Some(error) = envelope.error {
        return Some(McpText {
            text: error.message,
            is_error: true,
        });
    }

    let result = envelope.result?;
    let text = result
        .content
        .into_iter()
        .filter_map(|content| content.text)
        .collect::<Vec<_>>()
        .join("\n");
    (!text.is_empty()).then_some(McpText {
        text,
        is_error: result.is_error,
    })
}

fn parse_mcp_response(body: &str) -> Option<McpText> {
    let trimmed = body.trim();
    if trimmed.starts_with('{') {
        if let Some(result) = parse_mcp_payload(trimmed) {
            return Some(result);
        }
    }

    body.lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .find_map(parse_mcp_payload)
}

fn is_rate_limit_error(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("rate limit") || lower.contains("too many requests") || lower.contains("429")
}

/// Decode the MCP envelope and return its text verbatim. A provider-side
/// `isError` is surfaced as an error (rate limits mapped specifically) so the
/// LLM learns the search failed rather than trusting an error body as data.
fn decode_search_text(provider: WebSearchProvider, body: &str) -> Result<String, WebSearchError> {
    let result = parse_mcp_response(body).ok_or(WebSearchError::InvalidResponse { provider })?;
    if result.is_error {
        return if is_rate_limit_error(&result.text) {
            Err(WebSearchError::RateLimited { provider })
        } else {
            Err(WebSearchError::Unavailable { provider })
        };
    }
    Ok(result.text)
}

fn http_client() -> Result<&'static reqwest::Client, WebSearchError> {
    HTTP_CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .user_agent(concat!("fengheshell-ai-copilot/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|_| ())
        })
        .as_ref()
        .map_err(|_| WebSearchError::ClientBuild)
}

async fn read_response(
    response: reqwest::Response,
    provider: WebSearchProvider,
) -> Result<Vec<u8>, WebSearchError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(WebSearchError::ResponseTooLarge { provider });
    }

    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| WebSearchError::Unavailable { provider })?;
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(WebSearchError::ResponseTooLarge { provider });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn search_provider(
    provider: WebSearchProvider,
    endpoint: &str,
    query: &ValidatedQuery,
) -> Result<WebSearchResponse, WebSearchError> {
    let started = Instant::now();
    let response = http_client()?
        .post(endpoint)
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .json(&mcp_request(provider, query))
        .send()
        .await
        .map_err(|_| WebSearchError::Unavailable { provider })?;

    match response.status().as_u16() {
        200..=299 => {}
        401 | 403 => return Err(WebSearchError::Authentication { provider }),
        429 => return Err(WebSearchError::RateLimited { provider }),
        _ => return Err(WebSearchError::Unavailable { provider }),
    }

    let body = read_response(response, provider).await?;
    let body = String::from_utf8(body).map_err(|_| WebSearchError::InvalidResponse { provider })?;
    let text = decode_search_text(provider, &body)?;
    Ok(WebSearchResponse {
        // Never trust an upstream query echo for provenance. This is exactly
        // the locally redacted string sent across the network.
        query: query.query.clone(),
        provider: provider.id().to_owned(),
        text,
        elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
    })
}

/// 执行一次 web 检索。`routing_key` 只用于提供方二选一（负载均衡），
/// 调用方应传入稳定的会话级标识。
pub async fn search(
    input: &WebSearchInput,
    redact_rules: &[RedactRule],
    routing_key: &str,
) -> Result<WebSearchResponse, WebSearchError> {
    let query = build_query(input, redact_rules).map_err(WebSearchError::InvalidInput)?;
    let provider_override = std::env::var("FENGHESHELL_WEB_SEARCH_PROVIDER").ok();
    let provider = select_provider(routing_key, provider_override.as_deref());
    search_provider(provider, provider.endpoint(), &query).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn builds_a_bounded_redacted_search_query() {
        let query = build_query(
            &WebSearchInput {
                query: "  rust async patterns  ".into(),
                max_results: None,
            },
            &[],
        )
        .unwrap();

        assert_eq!(query.query, "rust async patterns");
        assert_eq!(query.limit, DEFAULT_RESULTS);
    }

    #[test]
    fn redacts_query_before_building_provider_query() {
        let rules = vec![RedactRule::new(r"EMP-\d{4}", "<REDACTED:employee>").unwrap()];

        let query = build_query(
            &WebSearchInput {
                query: "debug deployment for EMP-1234".into(),
                max_results: None,
            },
            &rules,
        )
        .unwrap();

        assert_eq!(query.query, "debug deployment for <REDACTED:employee>");
        assert!(!query.query.contains("EMP-1234"));
    }

    #[test]
    fn builtin_query_rules_cover_internal_ips() {
        let rules = builtin_query_rules();
        assert!(!rules.is_empty());

        let query = build_query(
            &WebSearchInput {
                query: "why is 10.0.0.5 unreachable".into(),
                max_results: None,
            },
            &rules,
        )
        .unwrap();
        assert!(!query.query.contains("10.0.0.5"));
        assert!(query.query.contains("<REDACTED:ip-10>"));
    }

    #[test]
    fn rejects_invalid_query_and_limits() {
        let input = |query: String, max_results| WebSearchInput { query, max_results };

        assert!(build_query(&input("   ".into(), None), &[]).is_err());
        assert!(build_query(&input("界".repeat(MAX_QUERY_CHARS + 1), None), &[]).is_err());
        assert!(build_query(&input("rust".into(), Some(0)), &[]).is_err());
        assert!(build_query(&input("rust".into(), Some(MAX_RESULTS + 1)), &[]).is_err());
    }

    #[test]
    fn rejects_query_that_is_empty_after_redaction() {
        let rules = vec![RedactRule::new(r"EMP-\d{4}", "").unwrap()];

        assert!(build_query(
            &WebSearchInput {
                query: "EMP-1234".into(),
                max_results: None,
            },
            &rules,
        )
        .is_err());
    }

    #[test]
    fn selects_a_provider_stably_and_honors_an_explicit_override() {
        assert_eq!(
            select_provider("conversation", Some("exa")),
            WebSearchProvider::Exa
        );
        assert_eq!(
            select_provider("conversation", Some("parallel")),
            WebSearchProvider::Parallel
        );
        assert_eq!(
            select_provider("conversation", None),
            select_provider("conversation", None)
        );

        let providers = (0..64)
            .map(|index| select_provider(&format!("conversation-{index}"), None))
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(providers.len(), 2);
    }

    #[test]
    fn builds_provider_specific_mcp_calls_without_session_metadata() {
        let query = ValidatedQuery {
            query: "rust async patterns".into(),
            limit: 8,
        };

        let exa = mcp_request(WebSearchProvider::Exa, &query);
        assert_eq!(exa["method"], "tools/call");
        assert_eq!(exa["params"]["name"], "web_search_exa");
        assert_eq!(exa["params"]["arguments"]["query"], query.query);
        assert_eq!(exa["params"]["arguments"]["numResults"], query.limit);

        let parallel = mcp_request(WebSearchProvider::Parallel, &query);
        assert_eq!(parallel["params"]["name"], "web_search");
        assert_eq!(
            parallel["params"]["arguments"]["search_queries"],
            json!([query.query])
        );
        assert!(parallel["params"]["arguments"].get("session_id").is_none());
        assert!(parallel["params"]["arguments"].get("model_name").is_none());
    }

    #[test]
    fn decodes_mcp_text_verbatim_from_an_sse_response() {
        let body = "event: message\ndata: {\"result\":{\"content\":[{\"text\":\"result one\"},{\"text\":\"result two\"}],\"isError\":false}}\n\n";
        let text = decode_search_text(WebSearchProvider::Exa, body).unwrap();
        assert_eq!(text, "result one\nresult two");
    }

    #[test]
    fn decodes_mcp_text_from_a_plain_json_response() {
        let body = r#"{"result":{"content":[{"text":"only result"}],"isError":false}}"#;
        let text = decode_search_text(WebSearchProvider::Parallel, body).unwrap();
        assert_eq!(text, "only result");
    }

    #[test]
    fn surfaces_provider_side_errors() {
        let rate_limited = r#"{"error":{"message":"429 rate limit exceeded"}}"#;
        assert!(matches!(
            decode_search_text(WebSearchProvider::Exa, rate_limited),
            Err(WebSearchError::RateLimited { .. })
        ));

        let failed = r#"{"error":{"message":"upstream exploded"}}"#;
        assert!(matches!(
            decode_search_text(WebSearchProvider::Exa, failed),
            Err(WebSearchError::Unavailable { .. })
        ));

        let garbage = "not json at all";
        assert!(matches!(
            decode_search_text(WebSearchProvider::Exa, garbage),
            Err(WebSearchError::InvalidResponse { .. })
        ));
    }
}

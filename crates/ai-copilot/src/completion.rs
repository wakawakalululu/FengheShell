//! 补全层的本地缓存。
//!
//! 补全请求很小（max_tokens 64），但它们是**逐击键**触发的：同一个前缀在
//! 一次排查里可能被问上十几次。缓存把「某个前缀 → 某次补全」记在本机内存里，
//! 命中就完全不走网络。
//!
//! 边界：
//! - 只存字符串，不存任何凭据；
//! - 容量与 TTL 双上限，进程退出即消失（不落盘）；
//! - 空结果也缓存 —— 「这个前缀没有更好的建议」同样值得记住。

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 默认最多缓存多少条前缀。
pub const DEFAULT_CAPACITY: usize = 256;
/// 默认多久之后认为一条缓存过期。
pub const DEFAULT_TTL: Duration = Duration::from_secs(10 * 60);

struct Entry {
    value: String,
    at: Instant,
}

struct Inner {
    /// key 是 `scope + '\n' + prefix`。
    map: HashMap<String, Entry>,
    /// 插入顺序，用于 LRU 淘汰（容量很小，线性操作足够）。
    order: VecDeque<String>,
}

/// 补全结果的进程内缓存。所有方法都是 `&self`，内部用锁，便于整体共享。
pub struct CompletionCache {
    inner: Mutex<Inner>,
    capacity: usize,
    ttl: Duration,
}

impl CompletionCache {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_CAPACITY, DEFAULT_TTL)
    }

    pub fn with_limits(capacity: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
            capacity: capacity.max(1),
            ttl,
        }
    }

    /// 命中返回缓存的补全（可能是空串，表示「模型当时给不出建议」），未命中返回 None。
    pub fn get(&self, scope: &str, prefix: &str) -> Option<String> {
        let key = Self::key(scope, prefix);
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let entry = inner.map.get(&key)?;
        if entry.at.elapsed() > self.ttl {
            // 过期：当作未命中，并顺手清掉。
            inner.order.retain(|k| k != &key);
            inner.map.remove(&key);
            return None;
        }
        let value = entry.value.clone();
        // 命中即视为最近使用。
        inner.order.retain(|k| k != &key);
        inner.order.push_back(key);
        Some(value)
    }

    /// 写入一条结果；`value` 为空串表示「无建议」，同样会被记住。
    pub fn insert(&self, scope: &str, prefix: &str, value: String) {
        let key = Self::key(scope, prefix);
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        inner.map.insert(
            key.clone(),
            Entry {
                value,
                at: Instant::now(),
            },
        );
        inner.order.retain(|k| k != &key);
        inner.order.push_back(key);
        while inner.map.len() > self.capacity {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            inner.map.remove(&oldest);
        }
    }

    pub fn clear(&self) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        inner.map.clear();
        inner.order.clear();
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.map.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn key(scope: &str, prefix: &str) -> String {
        format!("{scope}\n{prefix}")
    }
}

impl Default for CompletionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_returns_the_cached_completion_and_misses_return_none() {
        let cache = CompletionCache::new();
        assert_eq!(cache.get("m", "ps aux"), None);
        cache.insert("m", "ps aux", " --sort=-%cpu".into());
        assert_eq!(cache.get("m", "ps aux"), Some(" --sort=-%cpu".into()));
        // 空结果（无建议）也要被记住。
        cache.insert("m", "zzz", String::new());
        assert_eq!(cache.get("m", "zzz"), Some(String::new()));
    }

    #[test]
    fn scopes_are_isolated() {
        let cache = CompletionCache::new();
        cache.insert("model-a", "df", " -h".into());
        assert_eq!(cache.get("model-b", "df"), None);
        assert_eq!(cache.get("model-a", "df"), Some(" -h".into()));
    }

    #[test]
    fn capacity_evicts_the_least_recently_used_entry() {
        let cache = CompletionCache::with_limits(2, Duration::from_secs(600));
        cache.insert("m", "a", "1".into());
        cache.insert("m", "b", "2".into());
        // 读一次 a，让它变成最近使用。
        assert_eq!(cache.get("m", "a"), Some("1".into()));
        cache.insert("m", "c", "3".into());
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get("m", "b"), None, "b 是最久未用的，应该被淘汰");
        assert_eq!(cache.get("m", "a"), Some("1".into()));
        assert_eq!(cache.get("m", "c"), Some("3".into()));
    }

    #[test]
    fn expired_entries_are_dropped() {
        let cache = CompletionCache::with_limits(8, Duration::from_millis(1));
        cache.insert("m", "df", " -h".into());
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.get("m", "df"), None);
        assert!(cache.is_empty());
    }

    #[test]
    fn clear_empties_the_cache() {
        let cache = CompletionCache::new();
        cache.insert("m", "df", " -h".into());
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert!(cache.is_empty());
    }
}

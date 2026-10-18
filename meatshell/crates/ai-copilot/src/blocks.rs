//! 终端命令块（OSC 133 Shell Integration）解析 + AI 上下文环形缓冲。
//!
//! MeatShell 的只读 VT 终端本身不认识 OSC 133 语义块 —— 本模块在
//! PTY 输出流上覆盖一层轻量 FSM：识别 `ESC ] 133 ; A/B/C/D` 四个标记，
//! 把「上一条命令 + 输出 + 退出码」切成结构化 `CommandBlock`，供 AI
//! Triage 做精准上下文提取（而不是把十万行滚动缓冲扔给 LLM）。
//!
//! 标记语义（shell integration 事实标准，iTerm2/VSCode/Kitty 同款）：
//! - `A` prompt 开始（PS1 渲染起点）
//! - `B` 命令输入开始（光标就位，之后是用户输入回显）
//! - `C` 命令开始执行（按下回车）
//! - `D;<exit>` 命令结束（带退出码）
//!
//! PTY 分块会在任意字节边界切断转义序列，解析器用 `carry` 缓存不完整的
//! 尾部（OSC 未闭合 / CSI 未收尾），跨 `feed` 拼接。

use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use serde::Serialize;

/// 单个命令块的默认上下文预算：只截取最近 8KB（设计文档 §四.1 的防
/// Token 爆炸策略）。
pub const DEFAULT_CONTEXT_BYTES: usize = 8 * 1024;

const OSC133: &str = "\x1b]133;";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CommandBlock {
    /// 规范化后的命令（优先取 OSC 697 精确值，回退到 B→C 段回显清洗）。
    pub command: String,
    /// 命令输出（已剥离 ANSI）。
    pub output: String,
    /// 退出码（D 标记携带；缺省时 None）。
    pub exit_code: Option<i32>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    /// 执行时的 cwd（OSC 7 由会话层喂入，可选）。
    pub cwd: Option<String>,
    pub finished: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
enum Phase {
    /// 空闲（没有进行中的命令块） —— 必须是首变体：`Phase::default()` 才落到 Idle。
    #[default]
    Idle,
    /// A 之后：PS1 渲染中，文本丢弃
    Prompt,
    /// B 之后：用户输入回显中
    Input,
    /// C 之后：命令执行中
    Running,
}

enum Marker {
    A,
    B,
    C,
    D(Option<i32>),
}

/// 解析 PTY 文本流中的 OSC 133 标记，产出结构化命令块。
#[derive(Default)]
pub struct BlockParser {
    phase: Phase,
    /// 不完整的尾部转义序列（跨 feed 缓存）。
    carry: String,
    /// B→C 段的原始回显。
    echo: String,
    /// C→D 段的输出。
    output: String,
    /// OSC 697 提供的精确命令（优先级高于回显）。
    command_override: Option<String>,
    started_at: Option<DateTime<Utc>>,
    cwd: Option<String>,
}

impl BlockParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// 喂入一段 PTY 文本（可含任意 ANSI/OSC），返回本次新完成的命令块。
    pub fn feed(&mut self, text: &str) -> Vec<CommandBlock> {
        let mut buf = std::mem::take(&mut self.carry);
        buf.push_str(text);
        let mut finished = Vec::new();

        while let Some(idx) = buf.find(OSC133) {
            let seg = buf[..idx].to_string();
            self.push_segment(&seg);
            let after = &buf[idx + OSC133.len()..];
            match parse_marker(after) {
                Some((marker, consumed)) => {
                    if let Some(m) = marker {
                        if let Some(block) = self.on_marker(m) {
                            finished.push(block);
                        }
                    }
                    buf = after[consumed..].to_string();
                }
                // 标记本身被切断 —— 把 OSC 头一起留给下一次 feed。
                None => {
                    buf = format!("{OSC133}{after}");
                    break;
                }
            }
        }

        // 尾部可能残留不完整的 CSI/OSC，扣下来不消费。
        let hold = incomplete_escape_len(&buf);
        let split = buf.len() - hold;
        self.push_segment(&buf[..split]);
        self.carry = buf[split..].to_string();
        finished
    }

    /// 会话层解析到 OSC 697（精确命令历史）时调用，覆盖回显推断。
    pub fn set_command_override(&mut self, cmd: &str) {
        if self.phase == Phase::Input || self.phase == Phase::Running {
            self.command_override = Some(cmd.to_string());
        }
    }

    /// 会话层解析到 OSC 7（cwd）时调用。
    pub fn set_cwd(&mut self, cwd: String) {
        self.cwd = Some(cwd);
    }

    /// 当前是否有进行中的命令块（UI 可显示「运行中」指示）。
    pub fn busy(&self) -> bool {
        matches!(self.phase, Phase::Input | Phase::Running)
    }

    fn push_segment(&mut self, seg: &str) {
        if seg.is_empty() {
            return;
        }
        match self.phase {
            Phase::Input => self.echo.push_str(&strip_ansi(seg)),
            Phase::Running => self.output.push_str(&strip_ansi(seg)),
            Phase::Idle | Phase::Prompt => {}
        }
    }

    fn on_marker(&mut self, marker: Marker) -> Option<CommandBlock> {
        match marker {
            Marker::A => {
                // 上一个块没收尾（异常情况）——直接丢弃，开新块。
                if self.phase != Phase::Idle {
                    self.reset_current();
                }
                self.phase = Phase::Prompt;
                None
            }
            Marker::B => {
                if self.phase == Phase::Prompt || self.phase == Phase::Idle {
                    self.echo.clear();
                    self.output.clear();
                    self.command_override = None;
                    self.phase = Phase::Input;
                }
                None
            }
            Marker::C => {
                if self.phase == Phase::Input || self.phase == Phase::Prompt {
                    self.phase = Phase::Running;
                    self.started_at = Some(Utc::now());
                }
                None
            }
            Marker::D(code) => {
                let block = self.finish(code);
                self.reset_current();
                block
            }
        }
    }

    fn finish(&mut self, code: Option<i32>) -> Option<CommandBlock> {
        if self.phase == Phase::Idle {
            return None;
        }
        let command = self
            .command_override
            .clone()
            .unwrap_or_else(|| clean_echo(&self.echo));
        let started_at = self.started_at.unwrap_or_else(Utc::now);
        let now = Utc::now();
        Some(CommandBlock {
            command,
            output: self.output.trim_end_matches(['\n', '\r']).to_string(),
            exit_code: code,
            started_at,
            finished_at: Some(now),
            cwd: self.cwd.clone(),
            finished: true,
        })
    }

    fn reset_current(&mut self) {
        self.phase = Phase::Idle;
        self.echo.clear();
        self.output.clear();
        self.command_override = None;
        self.started_at = None;
    }
}

/// 解析 `after`（OSC133 头之后的内容）为 marker + 消费的字节数。
///
/// 形态：`A<BEL>`、`D;0<BEL>`、`D;0<ESC>\`、`B\x07` ……
/// 第一个字符必须是 A/B/C/D，否则视为非语义 OSC 133（理论上不会出现），
/// 按未知 OSC 消费到终止符为止。
/// 解析 `after`（OSC133 头之后的内容）。
///
/// 返回 `Some((Option<Marker>, 消费字节数))`：
/// - `Some((Some(m), n))` —— 语义标记 A/B/C/D 已完整解析
/// - `Some((None, n))` —— 未知的 133 扩展码，已完整消费，跳过
/// - `None` —— 序列尚未收尾（无 BEL / ST 终止符），等待后续字节
fn parse_marker(after: &str) -> Option<(Option<Marker>, usize)> {
    let bytes = after.as_bytes();
    let first = *bytes.first()? as char;
    let mut i = 1usize;
    let marker = match first {
        'A' => Some(Marker::A),
        'B' => Some(Marker::B),
        'C' => Some(Marker::C),
        'D' => {
            // D 可能带 `;<exit_code>`
            let mut code = None;
            if bytes.get(1) == Some(&b';') {
                i = 2;
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i > start {
                    code = after[start..i].parse::<i32>().ok();
                }
            }
            Some(Marker::D(code))
        }
        // 未知扩展码：找到终止符就整段消费，否则等待。
        _ => {
            let mut j = 1;
            while j < bytes.len() {
                if bytes[j] == 0x07 {
                    return Some((None, j + 1));
                }
                if bytes[j] == 0x1b && bytes.get(j + 1) == Some(&b'\\') {
                    return Some((None, j + 2));
                }
                j += 1;
            }
            return None;
        }
    };
    // 消费终止符：BEL 或 ESC \
    let mut consumed = i;
    if bytes.get(i) == Some(&0x07) {
        consumed += 1;
    } else if after[i..].starts_with("\x1b\\") {
        consumed += 2;
    } else {
        // 没有终止符 —— 标记不完整
        return None;
    }
    Some((marker, consumed))
}

/// 返回 `s` 尾部不完整转义序列的长度（需要 hold 回去等下一块）。
fn incomplete_escape_len(s: &str) -> usize {
    let Some(pos) = s.rfind('\x1b') else {
        return 0;
    };
    let tail = &s[pos..];
    let bytes = tail.as_bytes();
    if bytes.len() == 1 {
        return 1; // 裸 ESC
    }
    match bytes[1] {
        b']' => {
            if tail.contains('\x07') || tail.contains("\x1b\\") {
                0
            } else {
                tail.len()
            }
        }
        b'[' => {
            let complete = bytes[2..].iter().any(|b| (0x40..=0x7e).contains(b));
            if complete {
                0
            } else {
                tail.len()
            }
        }
        _ => 0, // 两字节转义假定完整
    }
}

/// 剥离 ANSI 转义序列（CSI / OSC / 两字节转义）与 \r。
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            0x1b => {
                i += 1;
                if i >= bytes.len() {
                    break;
                }
                match bytes[i] {
                    b'[' => {
                        // CSI：参数/中间字节直到 final byte 0x40..=0x7e
                        i += 1;
                        while i < bytes.len() && !(0x40..=0x7e).contains(&bytes[i]) {
                            i += 1;
                        }
                        if i < bytes.len() {
                            i += 1; // 吃掉 final byte
                        }
                    }
                    // OSC 与其余字符串型序列（DCS `ESC P` / PM `ESC ^` /
                    // APC `ESC _` / SOS `ESC X`）：payload 到 BEL 或 ST 为止，
                    // 内容全部丢弃 —— 它们是窗口标题 / 剪贴板 / 终端能力查询，
                    // 落进 LLM 上下文只会污染 token。
                    b']' | b'P' | b'^' | b'_' | b'X' => {
                        // OSC：直到 BEL 或 ESC \
                        i += 1;
                        while i < bytes.len() {
                            if bytes[i] == 0x07 {
                                i += 1;
                                break;
                            }
                            if bytes[i] == 0x1b && bytes.get(i + 1) == Some(&b'\\') {
                                i += 2;
                                break;
                            }
                            i += 1;
                        }
                    }
                    _ => {
                        // 字符集选择（ESC ( B）等：先吞掉中间字节 0x20..=0x2F，
                        // 再吞掉 final byte 0x30..=0x7E。少了后半步，`\x1b(Bplain`
                        // 会把字符集指示符 `B` 当成正文漏进输出。
                        while i < bytes.len() && (0x20..=0x2f).contains(&bytes[i]) {
                            i += 1;
                        }
                        if i < bytes.len() && (0x30..=0x7e).contains(&bytes[i]) {
                            i += 1;
                        }
                    }
                }
            }
            b'\r' => {
                i += 1;
            }
            _ => {
                // 原样拷贝一个完整 UTF-8 字符
                let ch_len = utf8_len(bytes[i]);
                out.push_str(&s[i..i + ch_len]);
                i += ch_len;
            }
        }
    }
    out
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

/// 清洗 B→C 段回显：去掉首尾空白与控制字符，压掉内部换行。
fn clean_echo(echo: &str) -> String {
    let mut s: String = echo
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .collect();
    // 回显通常以用户敲的回车结尾
    while s.ends_with(['\n', '\r', ' ']) {
        s.pop();
    }
    s.trim().to_string()
}

/// 最近的命令块环形缓冲，附 8KB 滑动窗口的 transcript 生成。
#[derive(Debug)]
pub struct ContextWindow {
    blocks: VecDeque<CommandBlock>,
    max_bytes: usize,
}

impl ContextWindow {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            blocks: VecDeque::new(),
            max_bytes,
        }
    }

    pub fn push(&mut self, block: CommandBlock) {
        self.blocks.push_back(block);
        self.trim();
    }

    fn trim(&mut self) {
        while self.total_bytes() > self.max_bytes && self.blocks.len() > 1 {
            self.blocks.pop_front();
        }
    }

    fn total_bytes(&self) -> usize {
        self.blocks.iter().map(block_bytes).sum()
    }

    pub fn blocks(&self) -> &VecDeque<CommandBlock> {
        &self.blocks
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// 生成送给 LLM 的终端上下文 transcript：
    /// 新块优先、总量受 `max_bytes` 约束、老块超预算时整块省略。
    pub fn transcript(&self) -> String {
        let mut out = String::new();
        for block in self.blocks.iter().rev() {
            let entry = format_block(block);
            if out.len() + entry.len() > self.max_bytes {
                if out.is_empty() {
                    // 连最新一块都超预算 —— 截断输出部分也要带上命令头
                    out.push_str(&truncate_block_for_budget(block, self.max_bytes));
                }
                break;
            }
            let mut next = entry;
            next.push_str(&out);
            out = next;
        }
        out
    }
}

fn block_bytes(b: &CommandBlock) -> usize {
    b.command.len() + b.output.len() + 16
}

fn format_block(b: &CommandBlock) -> String {
    let exit = b
        .exit_code
        .map(|c| c.to_string())
        .unwrap_or_else(|| "?".into());
    let cwd = b
        .cwd
        .as_ref()
        .map(|c| format!(" (cwd: {c})"))
        .unwrap_or_default();
    format!("$ {}{}\n[exit {exit}]\n{}\n", b.command, cwd, b.output)
}

fn truncate_block_for_budget(b: &CommandBlock, budget: usize) -> String {
    let head = format!(
        "$ {}\n[exit {}]\n",
        b.command,
        b.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "?".into())
    );
    if head.len() >= budget {
        return head;
    }
    // 截断标记本身也占预算 —— 不扣除的话 transcript 会超出调用方的上界。
    const MARKER: &str = "...[earlier output truncated]...\n";
    let output = tail_within_bytes(&b.output, budget - head.len() - MARKER.len());
    format!("{head}{MARKER}{output}")
}

/// 取 `s` 末尾累计不超过 `budget` **字节**的片段（不切断 UTF-8 字符）。
/// 预算按字节算而多字节字符会让 char 数 < 字节数，因此这里逐字符累加字节数。
fn tail_within_bytes(s: &str, budget: usize) -> String {
    let mut used = 0usize;
    let mut start = s.len();
    for (i, ch) in s.char_indices().rev() {
        if used + ch.len_utf8() > budget {
            break;
        }
        used += ch.len_utf8();
        start = i;
    }
    s[start..].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(m: &str) -> String {
        format!("\x1b]133;{m}\x07")
    }

    #[test]
    fn parses_single_command_block() {
        let mut p = BlockParser::new();
        let stream = format!(
            "{a}user@host:~$ {b}ls -l{c}total 8\n-rw file{d}",
            a = marker("A"),
            b = marker("B"),
            c = marker("C"),
            d = marker("D;0"),
        );
        let blocks = p.feed(&stream);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].command, "ls -l");
        assert_eq!(blocks[0].output, "total 8\n-rw file");
        assert_eq!(blocks[0].exit_code, Some(0));
        assert!(blocks[0].finished);
    }

    #[test]
    fn nonzero_exit_code_is_captured() {
        let mut p = BlockParser::new();
        let stream = format!(
            "{a}{b}grep -r foo /etc{c}no matches{d}",
            a = marker("A"),
            b = marker("B"),
            c = marker("C"),
            d = marker("D;2"),
        );
        let blocks = p.feed(&stream);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].exit_code, Some(2));
        assert_eq!(blocks[0].command, "grep -r foo /etc");
    }

    #[test]
    fn osc697_command_overrides_echo() {
        let mut p = BlockParser::new();
        // 回显不可靠（括号粘贴 / 长命令折行）时 OSC 697 给出精确命令。
        p.feed(&format!("{a}{b}", a = marker("A"), b = marker("B")));
        p.set_command_override("systemctl status nginx");
        let blocks = p.feed(&format!("{c}active (running){d}", c = marker("C"), d = marker("D;0")));
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].command, "systemctl status nginx");
    }

    #[test]
    fn marker_split_across_feeds_is_reassembled() {
        let mut p = BlockParser::new();
        assert!(p.feed("\x1b]133;A\x07").is_empty());
        // B 标记从中间切断
        assert!(p.feed("\x1b]13").is_empty());
        assert!(p.feed("3;B\x07").is_empty());
        // 命令回显
        assert!(p.feed("id").is_empty());
        // C 标记完整
        assert!(p.feed("\x1b]133;C\x07").is_empty());
        assert!(p.feed("uid=0").is_empty());
        // D;0 的退出码部分被切断
        assert!(p.feed("\x1b]133;D;").is_empty());
        let done = p.feed("0\x07");
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].command, "id");
        assert_eq!(done[0].output, "uid=0");
        assert_eq!(done[0].exit_code, Some(0));
    }

    #[test]
    fn csi_split_across_feeds_is_not_corrupted() {
        let mut p = BlockParser::new();
        p.feed(&marker("A"));
        p.feed(&marker("B"));
        p.feed(&marker("C"));
        let blocks = p.feed("out\x1b[31");
        assert!(blocks.is_empty());
        let blocks = p.feed("mred\x1b[0m tail\x1b]133;D;0\x07");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].output, "outred tail");
    }

    #[test]
    fn st_terminated_markers_work() {
        let mut p = BlockParser::new();
        // ST（ESC \）终止的标记 + B→C 之间的回显才是命令名。
        let stream = "\x1b]133;A\x1b\\\x1b]133;B\x1b\\hi\x1b]133;C\x1b\\out\x1b]133;D;1\x1b\\";
        let blocks = p.feed(stream);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].command, "hi");
        assert_eq!(blocks[0].output, "out");
        assert_eq!(blocks[0].exit_code, Some(1));
    }

    #[test]
    fn strip_ansi_removes_csi_osc_and_plain_escapes() {
        assert_eq!(strip_ansi("\x1b[1;32mok\x1b[0m"), "ok");
        assert_eq!(strip_ansi("\x1b]0;title\x07body"), "body");
        assert_eq!(strip_ansi("\x1b(Bplain"), "plain");
        assert_eq!(strip_ansi("a\r\nb"), "a\nb");
        assert_eq!(strip_ansi("中文\x1b[31m测试"), "中文测试");
    }

    #[test]
    fn context_window_transcript_respects_budget() {
        let mut w = ContextWindow::new(200);
        for i in 0..20 {
            w.push(CommandBlock {
                command: format!("cmd-{i}"),
                output: "x".repeat(40),
                exit_code: Some(0),
                started_at: Utc::now(),
                finished_at: Some(Utc::now()),
                cwd: None,
                finished: true,
            });
        }
        let t = w.transcript();
        assert!(t.len() <= 200, "transcript overflowed: {}", t.len());
        assert!(t.contains("cmd-19"), "newest block must survive");
    }

    #[test]
    fn single_oversized_block_is_truncated_not_dropped() {
        let mut w = ContextWindow::new(100);
        w.push(CommandBlock {
            command: "tail -n 10000 /var/log/big.log".into(),
            output: "y".repeat(10_000),
            exit_code: Some(0),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            cwd: None,
            finished: true,
        });
        let t = w.transcript();
        assert!(t.len() <= 120);
        assert!(t.starts_with("$ tail -n 10000"));
        assert!(t.contains("truncated"));
    }
}

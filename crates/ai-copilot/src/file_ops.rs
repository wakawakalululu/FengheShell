//! file_ops：`match_file` / `patch_file` 的远端命令构造（rssh 移植）。
//!
//! rssh 上游：`src-tauri/src/ai/session/file_ops.rs`。那里把「远端能力探测 +
//! 多行脚本装进单行 ASCII 命令 + 审批卡片编排」拆成独立子模块；本 crate 只移植
//! **纯逻辑**部分（引号转义、脚本模板、命令构造、能力解析、JSON marker 抽取），
//! 多步编排由 `triage.rs` 通过 `ToolRuntime` 完成（卡片 + PTY 执行）。
//!
//! ## 核心不变量
//!
//! 所有送进 PTY 的命令在 shell 视角下必须是**单行**（无字面 `\n` / `\r`），
//! 避开 zsh ZLE multi-line quote race（详见 `ansi_c_quote` 注释）。
//! 非 ASCII 字符（中文 / emoji）在 `$'...'` 内直接透传 —— bash / zsh 都按
//! UTF-8 解释字面字节，只有控制字符 / DEL / 单引号 / 反斜杠需要 `\xHH` 编码。
//!
//! ## 安全姿态
//!
//! 这些命令由**后端模板**拼装（不是 LLM 直传 shell），因此不过 shape validator
//! —— 与 rssh 一致：`run_file_op` 明确跳过 `sanitize::validate`，安全性由
//! 「固定模板 + 每步审批卡片 + 计数校验」保证。LLM 可控的只有 `find` /
//! `replace` 文本，全部经 `ansi_c_quote` 编码（控制字符 hex 化，防 terminal
//! escape injection）。

// ─── 远端能力探测 ─────────────────────────────────────────────────

/// 远端 file_ops 工具能力。探测一次后由调用方缓存（triage 引擎按 ask() 轮次缓存）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteCapabilities {
    /// `python3`（首选）
    pub python3: bool,
    /// `perl`（降级）—— `\Q...\E` 字面匹配
    pub perl: bool,
    /// `diff -u`（patch_file 出审批 diff 必备）
    pub diff: bool,
}

impl RemoteCapabilities {
    pub fn none() -> Self {
        Self {
            python3: false,
            perl: false,
            diff: false,
        }
    }
}

/// 探测命令：一行拿三个工具的可用性。输出形如 `py3=1 perl=1 diff=1`。
///
/// 宿主把它包上 sentinel 后写进**用户可见的 PTY**（与 rssh 的 internal_command
/// 一致：不弹卡片，但命令本身对用户透明）。
pub const PROBE_CMD: &str = r#"echo "py3=$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0) perl=$(command -v perl >/dev/null 2>&1 && echo 1 || echo 0) diff=$(command -v diff >/dev/null 2>&1 && echo 1 || echo 0)""#;

/// 解析探测命令输出 —— 找含 `py3=` `perl=` `diff=` 的那一行。
pub fn parse_capabilities(output: &str) -> RemoteCapabilities {
    let mut caps = RemoteCapabilities::none();
    for line in output.lines() {
        let line = line.trim();
        if !(line.contains("py3=") && line.contains("perl=") && line.contains("diff=")) {
            continue;
        }
        for token in line.split_whitespace() {
            if let Some(v) = token.strip_prefix("py3=") {
                caps.python3 = v == "1";
            } else if let Some(v) = token.strip_prefix("perl=") {
                caps.perl = v == "1";
            } else if let Some(v) = token.strip_prefix("diff=") {
                caps.diff = v == "1";
            }
        }
        return caps;
    }
    caps
}

// ─── JSON marker ─────────────────────────────────────────────────

/// JSON 输出包裹 marker：脚本把结果包在两个 marker 之间输出，
/// 后端用此 marker 从 PTY 字节流里精准切出 JSON，规避 shell prompt /
/// ANSI 序列 / 命令回显的干扰。
pub const JSON_MARKER: &str = "__MSAI_JSON__";

/// 从 PTY 原始输出里抽出由 `JSON_MARKER` 包裹的内容。
/// 找不到一对独立成行的 marker 返回 None。
///
/// **按"独立成行"匹配**，不是 rfind 子串。脚本字面量里有 `M="__MSAI_JSON__"` 这行，
/// 脚本协议把 marker 输出为**整行**（前后都是 `\n`）。如果用 rfind：
///   1. 脚本源码 `M = "..."` 那行 echo 回显（marker 子串嵌在 `M = "<marker>"`）
///   2. 脚本输出的开头 marker（整行）
///   3. 脚本输出的结尾 marker（整行）
///   4. **更危险**：match_file 的 context 字段如果含 marker 字面（用户在文件里写了
///      `__MSAI_JSON__` 注释），子串扫到的位置会在 JSON 内部切，破坏解析。
///
/// 按行匹配杜绝以上风险：只有"整行 trim 后等于 marker"的位置才算锚点。脚本输出的
/// marker 一定独占一行；echo 回显里的字面量永远嵌在更长的源码行里，不会误匹配；
/// JSON payload 里的 marker（包在引号 + 上下文里）也不会独占一行。
pub fn extract_json_payload(pty_output: &str) -> Option<&str> {
    // 找最后两个"整行等于 marker"的行，记录字节起止 offset，回切原 &str。
    let mut last: Option<(usize, usize)> = None;
    let mut prev: Option<(usize, usize)> = None;
    let mut cursor = 0;
    for raw_line in pty_output.split('\n') {
        let start = cursor;
        let end = cursor + raw_line.len();
        cursor = end + 1; // 跳过 `\n`
        if raw_line.trim() == JSON_MARKER {
            prev = last;
            last = Some((start, end));
        }
    }
    let (_, prev_end) = prev?;
    let (last_start, _) = last?;
    // prev_end 是前一个 marker 行的结束（不含 `\n`）；下一字符是 `\n`，跳过再取
    let body_start = prev_end + 1;
    if body_start > last_start {
        return None;
    }
    Some(pty_output[body_start..last_start].trim_matches('\n').trim())
}

// ─── 解释器脚本 ───────────────────────────────────────────────────

/// match_file 的 python3 脚本。位置参数：path find before after
///
/// 不走 base64：find 直接作为 argv 字符串透传。shell 端 `ansi_c_quote(find)` 保证
/// 引号 / 空格 / 换行等都安全（`$'...'` 把真换行编为 `\n` 字面 escape，命令仍单行）。
/// Python 拿到的 sys.argv[2] 就是原始 UTF-8 字符串。
///
/// **远端 cap = 50 matches**：count 仍记真实总命中数，但 matches 数组只装前 50 个 +
/// `truncated` 标识。理由：PTY 流要在 sentinel 出现前把全部 output buffer 住 ——
/// 短 find（如 "a"）配大文件（`/var/log/*`）可产 MB 级 JSON。在远端就 cap 才彻底安全。
const PYTHON_MATCH_SCRIPT: &str = r#"import sys,json
M="__MSAI_JSON__"
def o(x):sys.stdout.write(M+"\n"+json.dumps(x,ensure_ascii=False)+"\n"+M+"\n")
p=sys.argv[1];f=sys.argv[2];b=int(sys.argv[3]);a=int(sys.argv[4])
try:t=open(p,"rb").read().decode("utf-8")
except FileNotFoundError:o({"error":"file_not_found"});sys.exit(0)
except Exception as e:o({"error":"io_error","message":str(e)});sys.exit(0)
m=[];c=0;i=0;n=len(f);L=len(t);K=50
while True:
 j=t.find(f,i)
 if j<0:break
 c+=1
 if len(m)<K:
  m.append({"line":t.count("\n",0,j)+1,"context":t[max(0,j-b):min(L,j+n+a)]})
 i=j+n
r={"count":c,"matches":m}
if c>K:r["truncated"]=True;r["matches_shown"]=K
o(r)
"#;

/// patch_file Stage 2 的 python3 脚本（in-place 改 tmp）。位置参数：tmp_path find replace expected
/// 前置：shell 已 `cp path tmp`。脚本读 tmp → 校验 count → in-place 替换 → JSON {count}。
/// count 不匹配时删除 tmp，避免半成品残留。
const PYTHON_PATCH_SCRIPT: &str = r#"import sys,json,os
M="__MSAI_JSON__"
def o(x):sys.stdout.write(M+"\n"+json.dumps(x,ensure_ascii=False)+"\n"+M+"\n")
p=sys.argv[1];f=sys.argv[2];r=sys.argv[3];e=int(sys.argv[4])
try:t=open(p,"rb").read().decode("utf-8")
except Exception as ex:o({"error":"io_error","message":str(ex)});sys.exit(0)
c=t.count(f)
if c!=e:
 try:os.unlink(p)
 except Exception:pass
 o({"error":"count_mismatch","actual":c,"expected":e});sys.exit(0)
try:open(p,"wb").write(t.replace(f,r).encode("utf-8"))
except Exception as ex:o({"error":"tmp_write_failed","message":str(ex)});sys.exit(0)
o({"count":c})
"#;

/// match_file 的 perl 脚本（降级路径）。位置参数：path find before after
/// `\Q...\E` 把 find 当字面量匹配，跳过 regex 元字符。utf8::decode 让长度按字符算。
/// 同 PYTHON_MATCH_SCRIPT：远端 cap = 50 matches，count 仍记真实总数。
const PERL_MATCH_SCRIPT: &str = r#"use strict;use warnings;use JSON::PP;
my $M="__MSAI_JSON__";
sub o{print $M,"\n",encode_json($_[0]),"\n",$M,"\n"}
my($p,$f,$b,$a)=@ARGV;utf8::decode($f);
open(my $h,'<:raw',$p)or do{o({error=>"file_not_found"});exit 0};
local $/;my $t=<$h>;close $h;utf8::decode($t);
my @m;my $c=0;my $i=0;my $n=length($f);my $L=length($t);my $K=50;
while((my $j=index($t,$f,$i))>=0){
 $c++;
 if(scalar(@m)<$K){
  my $line=1+(()=substr($t,0,$j)=~/\n/g);
  my $pre=$j-$b;$pre=0 if $pre<0;my $post=$j+$n+$a;$post=$L if $post>$L;
  push @m,{line=>$line,context=>substr($t,$pre,$post-$pre)};
 }
 $i=$j+$n;
}
my %r=(count=>$c,matches=>\@m);
if($c>$K){$r{truncated}=JSON::PP::true;$r{matches_shown}=$K}
o(\%r);
"#;

/// patch_file Stage 2 的 perl 脚本（降级路径）。位置参数：tmp_path find replace expected
const PERL_PATCH_SCRIPT: &str = r#"use strict;use warnings;use JSON::PP;
my $M="__MSAI_JSON__";
sub o{print $M,"\n",encode_json($_[0]),"\n",$M,"\n"}
my($p,$f,$r,$e)=@ARGV;utf8::decode($f);utf8::decode($r);
open(my $h,'<:raw',$p)or do{o({error=>"io_error",message=>"$!"});exit 0};
local $/;my $t=<$h>;close $h;utf8::decode($t);
my $c=()=$t=~/\Q$f\E/g;
if($c!=$e){unlink($p);o({error=>"count_mismatch",actual=>$c,expected=>$e});exit 0}
my $new=$t;$new=~s/\Q$f\E/$r/g;utf8::encode($new);
open(my $w,'>:raw',$p)or do{o({error=>"tmp_write_failed",message=>"$!"});exit 0};
print $w $new;close $w;o({count=>$c});
"#;

// ─── Interpreter ─────────────────────────────────────────────────

/// file_ops 解释器：python3 优先，perl 降级。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interpreter {
    Python3,
    Perl,
}

impl Interpreter {
    pub fn binary(self) -> &'static str {
        match self {
            Self::Python3 => "python3",
            Self::Perl => "perl",
        }
    }

    /// `-c`（python3 inline script）或 `-e`（perl inline script）。
    fn script_flag(self) -> &'static str {
        match self {
            Self::Python3 => "-c",
            Self::Perl => "-e",
        }
    }

    /// 脚本字面量和位置参数之间的分隔符。
    ///
    /// Perl `-e` 之后 `@ARGV` 首元素若以 `-` 开头会被当未知 switch（"Unrecognized switch"），
    /// 必须 `--` 强制结束 switch 解析。
    ///
    /// Python `-c` 不消耗 `--` —— 加了反而让 `sys.argv[1]` 是字面 `--`，整个 argv 错位 1，
    /// 路径变成 `'--'` 让脚本读不到文件。
    fn args_prefix(self) -> &'static str {
        match self {
            Self::Python3 => "",
            Self::Perl => "-- ",
        }
    }

    fn match_script(self) -> &'static str {
        match self {
            Self::Python3 => PYTHON_MATCH_SCRIPT,
            Self::Perl => PERL_MATCH_SCRIPT,
        }
    }

    fn patch_script(self) -> &'static str {
        match self {
            Self::Python3 => PYTHON_PATCH_SCRIPT,
            Self::Perl => PERL_PATCH_SCRIPT,
        }
    }
}

/// 选 file_ops 解释器：python3 优先，perl 降级。都没就 None。
/// （diff 只有 patch_file 需要，单独由调用方校验。）
pub fn select_interpreter(caps: RemoteCapabilities) -> Option<Interpreter> {
    if caps.python3 {
        Some(Interpreter::Python3)
    } else if caps.perl {
        Some(Interpreter::Perl)
    } else {
        None
    }
}

// ─── Quoting & path helpers ──────────────────────────────────────

/// ANSI-C quoting (`$'...'`)：shell 把 `\n` `\t` `\\` 等转义序列展开为真字符，
/// 但**整段字面量在 shell 视角是单行 ASCII** —— 因此长多行脚本能塞进一条单行命令，
/// 不触发 zsh ZLE 的 multi-line quote race（粘贴长命令进 PTY 时 p10k 会渲染连续
/// quote> prompt、ZLE buffer 错乱、命令永不执行）。
///
/// **单引号编码为 `\x27`，不是 `\'`** —— 实测含多个 `\'` 的长命令在 zsh + p10k
/// 下偶发卡死（同一命令含 0 个 `\'` 时稳定通过）。怀疑 ZLE 在 `$'...'` 状态机内
/// 对 `\'` 的转义切换有 race。两者语义等价，但 transition 路径分离 —— hardening。
///
/// **其他 C0 控制字符（0x00-0x1F 中除 `\n`/`\r`/`\t` 外的）和 DEL (0x7F) 也 hex 化** ——
/// 安全：LLM 可控的 `find` / `replace` 含 ESC (`\x1b`) / BEL (`\x07`) / CSI 序列等会通过
/// PTY echo 触发 terminal escape injection（隐藏文本、伪造 prompt、改终端 title 等）。
/// 让 on-wire 命令保持 printable ASCII，回程的 PTY echo 也就不会被解释为 escape sequence。
/// 程序拿到的 argv 仍是原字节（shell 把 `\xHH` 解码回原 byte）。
///
/// 适用 bash / zsh（远端常见 shell）；POSIX 纯 sh / busybox sh / dash 不支持。
/// file_ops 已经硬依赖 python3 / perl，那些极简环境一般连解释器都没有，能力探测
/// 阶段就被拒。
pub fn ansi_c_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    out.push('$');
    out.push('\'');
    for ch in s.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\'' => out.push_str("\\x27"),
            '\\' => out.push_str("\\\\"),
            // 其他 C0 controls (0x00-0x1F 中未在上面特处理的) + DEL (0x7F) → \xHH
            c if (c as u32) < 0x20 || (c as u32) == 0x7F => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// POSIX 单引号转义。所有后端拼装的 PTY 命令都走这个，避免路径含
/// 空格/特殊字符时被 shell 错误解析。
///
/// 转义规则：把整个串包在单引号里；输入中的每个单引号替换为 `'\''`
/// （关闭引号 → 转义字面单引号 → 重开引号）。这是 POSIX shell 通用形态，
/// bash/dash/zsh/ash/busybox 都正确解析，且能可靠覆盖所有 shell 元字符
/// （$ ` * ? & | ; < > 等单引号内都按字面）。
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// 校验 path 不含会破坏单行命令的字符。
///
/// 必须拒：
/// - `\n` / `\r`：shell_quote 用 POSIX 单引号包，单引号内换行**字面保留**，命令字节流就有
///   真 `\n` byte，重新触发 zsh ZLE multi-line quote race —— 这正是拿 ansi_c_quote 把
///   脚本/find/replace 全单行化要规避的问题。path 走的是 shell_quote 不经 ansi_c_quote，必须
///   在入口直接拒。
/// - 其他 C0 控制字符 (0x00-0x1F) 和 DEL (0x7F)：terminal escape injection 防御（同 ansi_c_quote
///   注释里 ESC/BEL 的理由）。Unix 文件名理论上允许这些字符，但运维场景里它们没有合理用法。
pub fn validate_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty() {
        return Err("empty path");
    }
    for c in path.chars() {
        let code = c as u32;
        if c == '\n' || c == '\r' {
            return Err("path contains newline (\\n or \\r) — would break the single-line command");
        }
        if code < 0x20 || code == 0x7F {
            return Err("path contains control character");
        }
    }
    Ok(())
}

/// 远端文件路径准备：处理 `~` / `~/...` 前缀展开，其余走 shell_quote。
///
/// 直接 shell_quote `~/foo` → `'~/foo'`，单引号禁掉 `~` 展开，shell 看到字面波浪号
/// → 文件找不到。这里把 `~/` 替换为 `"$HOME"/`，让 `$HOME` 在双引号里展开，
/// 而 rest 部分仍走单引号保护特殊字符。
///
/// `~user/...` 形态（其他用户的 home）不支持 —— 这种用例罕见，按字面单引号处理
/// （LLM 想用就报"路径不存在"，明确的错误胜过悄悄改写）。
pub fn prepare_remote_path(path: &str) -> String {
    if path == "~" {
        "\"$HOME\"".to_string()
    } else if let Some(rest) = path.strip_prefix("~/") {
        format!("\"$HOME\"/{}", shell_quote(rest))
    } else {
        shell_quote(path)
    }
}

// ─── 命令构造 ────────────────────────────────────────────────────

/// 拼一条 `<interp> -c|-e $'...' [-- ] arg1 arg2 ...` 形态的解释器命令。
/// 单行 ASCII（脚本里的换行靠 `$'...'` 的 `\n` 编码），避免 PTY ZLE quote race。
fn build_script_cmd(interp: Interpreter, script: &str, args: &[String]) -> String {
    let args_part = if args.is_empty() {
        String::new()
    } else {
        format!(" {}{}", interp.args_prefix(), args.join(" "))
    };
    format!(
        "{} {} {}{}",
        interp.binary(),
        interp.script_flag(),
        ansi_c_quote(script),
        args_part,
    )
}

/// match_file 命令：搜索 path 中 find 出现的位置，回 JSON。
///
/// `find` 走 `ansi_c_quote` —— LLM 提供的 find 文本可能含真换行（如多行 YAML 块），
/// shell_quote 包后字面 `\n` byte 仍会出现在 shell 输入流里，触发 zsh ZLE 的
/// multi-line quote race。`$'...'` 把所有换行编码为 `\n` 转义序列，让命令在
/// shell 视角下保持单行 ASCII。
pub fn build_match_cmd(
    interp: Interpreter,
    path: &str,
    find: &str,
    before: u32,
    after: u32,
) -> String {
    build_script_cmd(
        interp,
        interp.match_script(),
        &[
            prepare_remote_path(path),
            ansi_c_quote(find),
            shell_quote(&before.to_string()),
            shell_quote(&after.to_string()),
        ],
    )
}

/// patch_file modify 命令：脚本在 tmp 上 in-place 替换，校验 count，回 JSON。
/// 前置：调用方已经独立跑过 `build_cp_cmd` 把原文复制到 tmp。
///
/// `find` / `replace` 都走 `ansi_c_quote`（理由同 `build_match_cmd`）。
pub fn build_modify_cmd(
    interp: Interpreter,
    tmp: &str,
    find: &str,
    replace: &str,
    expected: u32,
) -> String {
    build_script_cmd(
        interp,
        interp.patch_script(),
        &[
            prepare_remote_path(tmp),
            ansi_c_quote(find),
            ansi_c_quote(replace),
            shell_quote(&expected.to_string()),
        ],
    )
}

/// `\cp -- path tmp`：patch_file 第一步，把原文复制到同目录 tmp（保证后续 mv 单 rename(2)）。
///
/// **`\` 前缀**：远端用户可能配 `alias cp='cp -i'`/`alias mv='mv -i'`，互动询问会让
/// 命令挂到 timeout。bash/zsh 的转义命令头（`\cp` / `\mv`）跳过 alias 展开但仍命中
/// 真正可执行文件。`\diff` 同理（虽然 `alias diff='diff --color'` 一般不影响 exit）。
pub fn build_cp_cmd(path: &str, tmp: &str) -> String {
    format!(
        "\\cp -- {} {}",
        prepare_remote_path(path),
        prepare_remote_path(tmp)
    )
}

/// `\diff -u path tmp`：patch_file 第三步，给用户审批用的 unified diff。
/// exit 0=无差异 / 1=有差异（**正常**）/ ≥2=工具失败 —— 调用方必须按此判，不能套
/// "exit != 0 ⇒ 错误"的通用规则。
pub fn build_diff_cmd(path: &str, tmp: &str) -> String {
    format!(
        "\\diff -u -- {} {}",
        prepare_remote_path(path),
        prepare_remote_path(tmp)
    )
}

/// `\mv -- tmp path`：patch_file 最后一步，原子覆盖。
pub fn build_mv_cmd(tmp: &str, path: &str) -> String {
    format!(
        "\\mv -- {} {}",
        prepare_remote_path(tmp),
        prepare_remote_path(path)
    )
}

/// patch_file 的临时文件名：与 path 同目录，保证后续 mv 走单 rename(2)（同 filesystem，原子）。
/// 形态 `<path>.fengheshell-<8 hex>`。
pub fn build_tmp_path(path: &str) -> String {
    let suffix: String = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(8)
        .collect();
    format!("{path}.fengheshell-{suffix}")
}

// ─── 远端 JSON 结果结构 ──────────────────────────────────────────
// 注：match_file 的远端 JSON（`{ count, matches, truncated? }`）由 triage.rs
// 以 serde_json::Value 解析后原样转发给 LLM（与上游一致），这里不复制一份
// 结构体出来 —— 少一处会与远端脚本漂移的镜像。

#[cfg(test)]
mod tests {
    use super::*;

    // ─── shell_quote ────────────────────────────────────────────────

    #[test]
    fn shell_quote_plain_string() {
        assert_eq!(shell_quote("hello"), "'hello'");
        assert_eq!(shell_quote("/tmp/foo.yml"), "'/tmp/foo.yml'");
    }

    #[test]
    fn shell_quote_empty_string() {
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn shell_quote_with_spaces() {
        assert_eq!(shell_quote("/tmp/has space/foo"), "'/tmp/has space/foo'");
    }

    #[test]
    fn shell_quote_single_quote_escape() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("'"), "''\\'''");
        assert_eq!(shell_quote("a'b'c"), "'a'\\''b'\\''c'");
    }

    #[test]
    fn shell_quote_double_quote_passthrough() {
        assert_eq!(shell_quote(r#"say "hi""#), r#"'say "hi"'"#);
    }

    #[test]
    fn shell_quote_dollar_and_backtick_neutralized() {
        assert_eq!(shell_quote("$HOME"), "'$HOME'");
        assert_eq!(shell_quote("`whoami`"), "'`whoami`'");
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
    }

    #[test]
    fn shell_quote_shell_metacharacters_inert() {
        assert_eq!(shell_quote("a|b&c;d"), "'a|b&c;d'");
        assert_eq!(shell_quote("> /etc/passwd"), "'> /etc/passwd'");
        assert_eq!(shell_quote("*"), "'*'");
        assert_eq!(shell_quote("~/foo"), "'~/foo'");
    }

    #[test]
    fn shell_quote_backslash_passthrough() {
        assert_eq!(shell_quote(r"a\b"), r"'a\b'");
        assert_eq!(shell_quote(r"\n"), r"'\n'");
    }

    #[test]
    fn shell_quote_multibyte_chars() {
        assert_eq!(shell_quote("文件名.txt"), "'文件名.txt'");
        assert_eq!(shell_quote("emoji 🦀"), "'emoji 🦀'");
    }

    // ─── validate_path ──────────────────────────────────────────────

    #[test]
    fn validate_path_rejects_newline_and_cr() {
        assert!(validate_path("foo\nbar").is_err());
        assert!(validate_path("foo\rbar").is_err());
        assert!(validate_path("a\r\nb").is_err());
    }

    #[test]
    fn validate_path_rejects_other_c0_and_del() {
        assert!(validate_path("foo\x1bbar").is_err());
        assert!(validate_path("foo\x07bar").is_err());
        assert!(validate_path("foo\x00bar").is_err());
        assert!(validate_path("foo\x7fbar").is_err());
    }

    #[test]
    fn validate_path_rejects_empty() {
        assert!(validate_path("").is_err());
    }

    #[test]
    fn validate_path_passes_normal_paths() {
        assert!(validate_path("/etc/hosts").is_ok());
        assert!(validate_path("~/foo.yml").is_ok());
        assert!(validate_path("/tmp/has space/file").is_ok());
        assert!(validate_path("文件名.txt").is_ok());
        assert!(validate_path("a'b").is_ok());
        assert!(validate_path("*.log").is_ok());
    }

    // ─── prepare_remote_path（~ 路径展开） ──────────────────────────

    #[test]
    fn prepare_path_plain_passes_through_to_shell_quote() {
        assert_eq!(prepare_remote_path("/tmp/foo"), "'/tmp/foo'");
        assert_eq!(prepare_remote_path("foo"), "'foo'");
    }

    #[test]
    fn prepare_path_bare_tilde_expands_to_home() {
        assert_eq!(prepare_remote_path("~"), "\"$HOME\"");
    }

    #[test]
    fn prepare_path_tilde_slash_expands_then_quotes_rest() {
        assert_eq!(prepare_remote_path("~/foo"), "\"$HOME\"/'foo'");
        assert_eq!(prepare_remote_path("~/a/b/c.yml"), "\"$HOME\"/'a/b/c.yml'");
    }

    #[test]
    fn prepare_path_tilde_with_special_chars_in_rest() {
        assert_eq!(
            prepare_remote_path("~/has space/file"),
            "\"$HOME\"/'has space/file'"
        );
        assert_eq!(
            prepare_remote_path("~/it's.txt"),
            r#""$HOME"/'it'\''s.txt'"#
        );
    }

    #[test]
    fn prepare_path_other_user_home_not_expanded() {
        assert_eq!(prepare_remote_path("~root/foo"), "'~root/foo'");
        assert_eq!(prepare_remote_path("~user"), "'~user'");
    }

    #[test]
    fn prepare_path_tilde_in_middle_not_expanded() {
        assert_eq!(prepare_remote_path("/foo/~/bar"), "'/foo/~/bar'");
        assert_eq!(prepare_remote_path("foo~bar"), "'foo~bar'");
    }

    // ─── parse_capabilities ─────────────────────────────────────────

    #[test]
    fn parse_caps_all_present() {
        let r = parse_capabilities("py3=1 perl=1 diff=1\n");
        assert!(r.python3 && r.perl && r.diff);
    }

    #[test]
    fn parse_caps_only_python3() {
        let r = parse_capabilities("py3=1 perl=0 diff=0\n");
        assert!(r.python3 && !r.perl && !r.diff);
    }

    #[test]
    fn parse_caps_only_perl() {
        let r = parse_capabilities("py3=0 perl=1 diff=0\n");
        assert!(!r.python3 && r.perl && !r.diff);
        assert_eq!(select_interpreter(r), Some(Interpreter::Perl));
    }

    #[test]
    fn parse_caps_none() {
        let r = parse_capabilities("py3=0 perl=0 diff=0\n");
        assert!(!r.python3 && !r.perl && !r.diff);
        assert_eq!(select_interpreter(r), None);
    }

    #[test]
    fn parse_caps_tolerates_pty_noise() {
        let out = "user@host:~$ echo \"py3=...\"\npy3=1 perl=1 diff=1\nuser@host:~$ \n";
        let r = parse_capabilities(out);
        assert!(r.python3 && r.perl && r.diff);
    }

    #[test]
    fn parse_caps_missing_field_defaults_false() {
        let r = parse_capabilities("py3=1 perl=1");
        assert!(!r.python3 && !r.perl && !r.diff);
    }

    #[test]
    fn parse_caps_non_one_treated_as_false() {
        let r = parse_capabilities("py3=yes perl=2 diff=true");
        assert!(!r.python3 && !r.perl && !r.diff);
    }

    #[test]
    fn parse_caps_empty_input() {
        let r = parse_capabilities("");
        assert!(!r.python3 && !r.perl && !r.diff);
    }

    // ─── select_interpreter ─────────────────────────────────────────

    #[test]
    fn select_interp_python3_wins() {
        let caps = RemoteCapabilities {
            python3: true,
            perl: true,
            diff: true,
        };
        assert_eq!(select_interpreter(caps), Some(Interpreter::Python3));
    }

    #[test]
    fn select_interp_perl_alone_ok_for_match() {
        let caps = RemoteCapabilities {
            python3: false,
            perl: true,
            diff: false,
        };
        assert_eq!(select_interpreter(caps), Some(Interpreter::Perl));
    }

    #[test]
    fn select_interp_none_without_interp() {
        let caps = RemoteCapabilities {
            python3: false,
            perl: false,
            diff: true,
        };
        assert_eq!(select_interpreter(caps), None);
    }

    // ─── extract_json_payload ───────────────────────────────────────

    #[test]
    fn extract_json_basic() {
        let pty =
            "shell echo\n__MSAI_JSON__\n{\"count\":3,\"matches\":[]}\n__MSAI_JSON__\nsentinel:0\n";
        assert_eq!(
            extract_json_payload(pty),
            Some("{\"count\":3,\"matches\":[]}")
        );
    }

    #[test]
    fn extract_json_with_pty_noise() {
        let pty = "\x1b[?2004l\rprefix\n__MSAI_JSON__\n{\"a\":1}\n__MSAI_JSON__\r\nsentinel\n";
        assert_eq!(extract_json_payload(pty), Some("{\"a\":1}"));
    }

    #[test]
    fn extract_json_missing_returns_none() {
        assert!(extract_json_payload("no markers here").is_none());
        assert!(extract_json_payload("__MSAI_JSON__\nonly one marker\n").is_none());
    }

    #[test]
    fn extract_json_ignores_marker_literal_in_echoed_script() {
        // Regression: shell ECHO 会把脚本源码一并回显，脚本里 `M = "__MSAI_JSON__"`
        // 那行会作为 echo 的一部分进入 buffer。此时 buffer 含 3 个 marker：
        // 1 个 echo 字面量 + 2 个脚本真正输出。必须抽脚本输出的那对。
        let pty = "\
python3 -c 'import sys\n\
M = \"__MSAI_JSON__\"\n\
print(M); print(\"payload\"); print(M)'\n\
__MSAI_JSON__\n\
{\"count\":5,\"matches\":[{\"line\":84}]}\n\
__MSAI_JSON__\n\
__msai_done_abc:0\n";
        assert_eq!(
            extract_json_payload(pty),
            Some("{\"count\":5,\"matches\":[{\"line\":84}]}")
        );
    }

    #[test]
    fn extract_json_ignores_marker_literal_inside_json_payload() {
        // Regression：之前用 rfind 子串。如果用户文件里写了 `__MSAI_JSON__` 注释，
        // match_file 把 context 字段塞进 JSON 输出 —— rfind 会扫到 JSON 内部的 marker 子串，
        // 在 JSON 中间切，破坏解析。按"独立成行"匹配杜绝这个。
        let pty = "\
__MSAI_JSON__\n\
{\"count\":1,\"matches\":[{\"line\":3,\"context\":\"# note: __MSAI_JSON__ is fengheshell internal\"}]}\n\
__MSAI_JSON__\n\
__msai_done_xyz:0\n";
        assert_eq!(
            extract_json_payload(pty),
            Some("{\"count\":1,\"matches\":[{\"line\":3,\"context\":\"# note: __MSAI_JSON__ is fengheshell internal\"}]}")
        );
    }

    #[test]
    fn extract_json_takes_last_pair_when_buffer_contains_multiple_runs() {
        let pty = "\
__MSAI_JSON__\n{\"call\":\"first\"}\n__MSAI_JSON__\n\
some interleaved noise\n\
__MSAI_JSON__\n{\"call\":\"second\"}\n__MSAI_JSON__\n";
        assert_eq!(extract_json_payload(pty), Some("{\"call\":\"second\"}"));
    }

    // ─── ansi_c_quote ───────────────────────────────────────────────

    #[test]
    fn ansi_c_quote_empty() {
        assert_eq!(ansi_c_quote(""), "$''");
    }

    #[test]
    fn ansi_c_quote_plain_ascii() {
        assert_eq!(ansi_c_quote("hello world"), "$'hello world'");
    }

    #[test]
    fn ansi_c_quote_newline_becomes_escape() {
        assert_eq!(ansi_c_quote("a\nb"), "$'a\\nb'");
        assert_eq!(
            ansi_c_quote("line1\nline2\nline3"),
            "$'line1\\nline2\\nline3'"
        );
    }

    #[test]
    fn ansi_c_quote_single_quote_uses_hex_escape() {
        assert_eq!(ansi_c_quote("it's"), r"$'it\x27s'");
        assert_eq!(ansi_c_quote("'"), r"$'\x27'");
        let q = ansi_c_quote("a'b'c'd");
        assert!(!q.contains(r"\'"), "must not produce \\' (hardening): {q}");
    }

    #[test]
    fn ansi_c_quote_backslash_doubles() {
        assert_eq!(ansi_c_quote(r"a\b"), r"$'a\\b'");
    }

    #[test]
    fn ansi_c_quote_tab_and_cr() {
        assert_eq!(ansi_c_quote("a\tb"), "$'a\\tb'");
        assert_eq!(ansi_c_quote("a\rb"), "$'a\\rb'");
    }

    #[test]
    fn ansi_c_quote_hex_escapes_c0_controls() {
        assert_eq!(ansi_c_quote("\x1b[31mRED"), "$'\\x1b[31mRED'");
        assert_eq!(ansi_c_quote("\x07bell"), "$'\\x07bell'");
        assert_eq!(ansi_c_quote("\x00NUL"), "$'\\x00NUL'");
        assert_eq!(ansi_c_quote("\x7fDEL"), "$'\\x7fDEL'");
        assert_eq!(ansi_c_quote("a\nb"), "$'a\\nb'");
        assert_eq!(
            ansi_c_quote("\x1b]0;evil title\x07\nok"),
            "$'\\x1b]0;evil title\\x07\\nok'"
        );
    }

    #[test]
    fn ansi_c_quote_multibyte_passthrough() {
        assert_eq!(ansi_c_quote("中文"), "$'中文'");
        assert_eq!(ansi_c_quote("🦀"), "$'🦀'");
    }

    #[test]
    fn ansi_c_quote_shell_metachars_inert() {
        // $ ` 等在 $'...' 内不展开（跟 "$..." 不同）
        assert_eq!(ansi_c_quote("$HOME"), "$'$HOME'");
        assert_eq!(ansi_c_quote("`whoami`"), "$'`whoami`'");
    }

    #[test]
    fn ansi_c_quote_script_stays_single_line_ascii() {
        let quoted = ansi_c_quote(PYTHON_MATCH_SCRIPT);
        assert!(!quoted.contains('\n'), "ansi_c_quote leaked real newline");
        assert!(!quoted.contains('\r'));
        assert!(quoted.starts_with("$'"));
        assert!(quoted.ends_with('\''));
    }

    #[test]
    fn ansi_c_quote_preserves_leading_spaces() {
        // 回归保护：patch_file 的 replace 经常是 YAML / config 块，缩进 2/4/6 空格混合。
        // ansi_c_quote 透传空格 byte，不能压缩 / 折叠，否则 shell 解析回来给 Python argv
        // 的字符串缩进塌掉，patch 写出来的文件就乱了。
        let yaml = "  - job_name: \"x\"\n    scrape_interval: 1s\n      - targets: [\"h:80\"]";
        let q = ansi_c_quote(yaml);
        let orig = yaml.bytes().filter(|&b| b == b' ').count();
        let got = q.bytes().filter(|&b| b == b' ').count();
        assert_eq!(orig, got, "spaces lost: {orig} → {got}, quoted={q}");
        assert!(q.contains("$'  - job_name:"), "L1 leading 2 spaces dropped");
        assert!(
            q.contains("\\n    scrape_interval"),
            "L2 leading 4 spaces dropped"
        );
        assert!(
            q.contains("\\n      - targets"),
            "L3 leading 6 spaces dropped"
        );
    }

    // ─── build_match_cmd / build_modify_cmd / build_cp_cmd / build_diff_cmd / build_mv_cmd ───

    #[test]
    fn build_match_cmd_python3_form() {
        let cmd = build_match_cmd(Interpreter::Python3, "/etc/foo.yml", "old", 80, 80);
        assert!(cmd.starts_with("python3 -c $'"), "got: {cmd}");
        assert!(cmd.contains("'/etc/foo.yml'"));
        assert!(cmd.contains("$'old'"));
        assert!(cmd.contains("'80'"));
        assert!(!cmd.contains('\n'), "cmd has real newline: {cmd}");
    }

    #[test]
    fn build_match_cmd_perl_form() {
        let cmd = build_match_cmd(Interpreter::Perl, "/etc/foo.yml", "old", 80, 80);
        assert!(cmd.starts_with("perl -e $'"), "got: {cmd}");
        assert!(!cmd.contains('\n'));
    }

    #[test]
    fn build_match_cmd_python3_omits_arg_separator() {
        // Regression: Python `-c` 不消耗 `--`，加上去会让 sys.argv[1] 变成字面 '--'。
        let cmd = build_match_cmd(Interpreter::Python3, "/etc/foo.yml", "old", 80, 80);
        assert!(
            !cmd.contains(" -- '/etc/foo.yml'"),
            "Python 路径 path 前不应有 `--`：{cmd}"
        );
    }

    #[test]
    fn build_match_cmd_perl_keeps_arg_separator() {
        let cmd = build_match_cmd(Interpreter::Perl, "/etc/foo.yml", "old", 80, 80);
        assert!(
            cmd.contains(" -- '/etc/foo.yml'"),
            "Perl 脚本 + path 之间必须有 `--`：{cmd}"
        );
    }

    #[test]
    fn build_match_cmd_tilde_path_expands() {
        let cmd = build_match_cmd(Interpreter::Python3, "~/foo.yml", "x", 10, 10);
        assert!(cmd.contains("\"$HOME\"/'foo.yml'"));
    }

    #[test]
    fn build_match_cmd_find_with_newline_stays_single_line() {
        let cmd = build_match_cmd(Interpreter::Python3, "/p", "line1\nline2", 0, 0);
        assert!(!cmd.contains('\n'), "newline leaked into cmd: {cmd}");
        assert!(cmd.contains(r"$'line1\nline2'"));
    }

    #[test]
    fn build_match_cmd_find_with_shell_metachars_no_expansion() {
        let cmd = build_match_cmd(Interpreter::Python3, "/p", "$HOME `whoami`", 0, 0);
        assert!(cmd.contains("$'$HOME `whoami`'"));
    }

    #[test]
    fn build_modify_cmd_python3_form() {
        let cmd = build_modify_cmd(Interpreter::Python3, "/p.tmp", "old", "new", 3);
        assert!(cmd.starts_with("python3 -c $'"), "got: {cmd}");
        assert!(cmd.contains("'/p.tmp'"));
        assert!(cmd.contains("$'old'"));
        assert!(cmd.contains("$'new'"));
        assert!(cmd.contains("'3'"));
        assert!(!cmd.contains('\n'));
    }

    #[test]
    fn build_modify_cmd_perl_form() {
        let cmd = build_modify_cmd(Interpreter::Perl, "/p.tmp", "old", "new", 1);
        assert!(cmd.starts_with("perl -e $'"), "got: {cmd}");
        assert!(cmd.contains(" -- '/p.tmp'"), "got: {cmd}");
        assert!(!cmd.contains('\n'));
    }

    #[test]
    fn build_modify_cmd_handles_replace_with_newline() {
        let cmd = build_modify_cmd(Interpreter::Python3, "/p.tmp", "k: 1", "k: 2\nk2: 3", 1);
        assert!(!cmd.contains('\n'), "newline leaked: {cmd}");
        assert!(cmd.contains(r"$'k: 2\nk2: 3'"));
    }

    #[test]
    fn build_modify_cmd_handles_special_chars_in_path() {
        let cmd = build_modify_cmd(Interpreter::Python3, "/has space/it's.tmp", "x", "y", 1);
        assert!(cmd.contains(r"'/has space/it'\''s.tmp'"));
    }

    #[test]
    fn build_cp_cmd_form() {
        let cmd = build_cp_cmd("/p", "/p.fengheshell-abc12345");
        assert_eq!(cmd, r"\cp -- '/p' '/p.fengheshell-abc12345'");
    }

    #[test]
    fn build_cp_cmd_with_tilde() {
        let cmd = build_cp_cmd("~/foo", "~/foo.tmp");
        assert_eq!(cmd, "\\cp -- \"$HOME\"/'foo' \"$HOME\"/'foo.tmp'");
    }

    #[test]
    fn build_cp_cmd_with_special_chars() {
        let cmd = build_cp_cmd("/has space/it's", "/has space/it's.tmp");
        assert_eq!(cmd, r"\cp -- '/has space/it'\''s' '/has space/it'\''s.tmp'");
    }

    #[test]
    fn build_diff_cmd_form() {
        let cmd = build_diff_cmd("/p", "/p.tmp");
        assert_eq!(cmd, r"\diff -u -- '/p' '/p.tmp'");
    }

    #[test]
    fn build_diff_cmd_with_tilde() {
        let cmd = build_diff_cmd("~/foo", "~/foo.tmp");
        assert_eq!(cmd, "\\diff -u -- \"$HOME\"/'foo' \"$HOME\"/'foo.tmp'");
    }

    #[test]
    fn build_mv_cmd_form() {
        let cmd = build_mv_cmd("/p.fengheshell-abc12345", "/p");
        assert_eq!(cmd, r"\mv -- '/p.fengheshell-abc12345' '/p'");
    }

    #[test]
    fn build_mv_cmd_with_tilde() {
        let cmd = build_mv_cmd("~/foo.tmp", "~/foo");
        assert_eq!(cmd, "\\mv -- \"$HOME\"/'foo.tmp' \"$HOME\"/'foo'");
    }

    #[test]
    fn build_tmp_path_keeps_same_directory_and_adds_suffix() {
        let tmp = build_tmp_path("/etc/app/config.yml");
        assert!(tmp.starts_with("/etc/app/config.yml.fengheshell-"));
        assert_eq!(tmp.len(), "/etc/app/config.yml.fengheshell-".len() + 8);
        // 纯 hex 后缀（uuid simple 是小写 hex）
        let suffix = &tmp["/etc/app/config.yml.fengheshell-".len()..];
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ─── 远端脚本模板 ───────────────────────────────────────────────

    #[test]
    fn scripts_embed_the_fengheshell_marker() {
        for script in [
            PYTHON_MATCH_SCRIPT,
            PYTHON_PATCH_SCRIPT,
            PERL_MATCH_SCRIPT,
            PERL_PATCH_SCRIPT,
        ] {
            assert!(
                script.contains(JSON_MARKER),
                "script must emit the JSON marker"
            );
        }
    }

    #[test]
    fn probe_command_reports_all_three_tools() {
        assert!(PROBE_CMD.contains("command -v python3"));
        assert!(PROBE_CMD.contains("command -v perl"));
        assert!(PROBE_CMD.contains("command -v diff"));
    }
}

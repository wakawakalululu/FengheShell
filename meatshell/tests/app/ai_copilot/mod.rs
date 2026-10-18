//! app/ai.rs 的纯逻辑单测：命令块抽取 + sentinel 执行捕获。
//!不需要 Slint / SSH —— 只喂文本。

use super::*;

#[test]
fn shell_hook_fallback_builds_blocks() {
    let mut ai = TabAi::new();
    // SSH 会话里 MeatShell 的 hook 在每条命令跑完后报 OSC 697。
    ai.feed_output("ls -l\r\ntotal 8\r\n-rw-r--r-- 1 u g 12 f.txt\r\n");
    ai.note_command("ls -l");
    ai.feed_output("df -h\r\nFilesystem Size\r\n/dev/sda1 40G\r\n");
    ai.note_command("df -h");

    let blocks = ai.context_blocks(8);
    assert_eq!(blocks.len(), 2);
    // 回显的命令本身要被剥掉，回车要归一成 LF。
    assert_eq!(blocks[0].command, "ls -l");
    assert_eq!(blocks[0].output, "total 8\n-rw-r--r-- 1 u g 12 f.txt");
    assert_eq!(blocks[0].exit_code, None);
    assert_eq!(blocks[1].command, "df -h");
    assert_eq!(blocks[1].output, "Filesystem Size\n/dev/sda1 40G");
}

#[test]
fn own_sentinel_commands_stay_out_of_the_context() {
    let mut ai = TabAi::new();
    ai.feed_output("Filesystem\r\n");
    // Run Gate 注入的命令带 sentinel marker，不该污染 AI 上下文。
    ai.note_command("df -h; echo \"__msai_ab12:$?\"");
    assert!(ai.context_blocks(8).is_empty());
}

#[test]
fn exec_capture_reads_exit_code_from_the_sentinel_line() {
    let mut ai = TabAi::new();
    ai.arm_exec("__msai_ab12");
    ai.feed_output("Filesystem\r\n/dev/sda1 40G\r\n");
    // sentinel 还没出现 —— 继续等。
    assert!(ai.take_finished_exec().is_none());
    ai.feed_output("\x1b[32m__msai_ab12:0\x1b[0m\r\n");
    let (output, exit) = ai
        .take_finished_exec()
        .expect("sentinel line closes the capture");
    assert_eq!(exit, Some(0));
    assert_eq!(output, "Filesystem\n/dev/sda1 40G\n");
    // 取走之后监听就结束了，不会重复结算。
    assert!(ai.take_finished_exec().is_none());
}

#[test]
fn exec_capture_reports_nonzero_exit() {
    let mut ai = TabAi::new();
    ai.arm_exec("__msai_cd34");
    ai.feed_output("ls: cannot access /nope: No such file or directory\r\n__msai_cd34:2\r\n");
    let (output, exit) = ai.take_finished_exec().unwrap();
    assert_eq!(exit, Some(2));
    assert_eq!(output, "ls: cannot access /nope: No such file or directory\n");
}

#[test]
fn osc133_markers_win_over_the_hook_fallback() {
    let mut ai = TabAi::new();
    ai.feed_output("\x1b]133;A\x07\x1b]133;B\x07whoami\x1b]133;C\x07root\n\x1b]133;D;0\x07");
    let blocks = ai.context_blocks(4);
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].command, "whoami");
    assert_eq!(blocks[0].exit_code, Some(0));
    // 从此不再走 hook 兜底，避免同一段命令被记两次。
    ai.note_command("whoami");
    assert_eq!(ai.context_blocks(4).len(), 1);
}

#[test]
fn cancel_invalidates_waiting_approval() {
    let mut ai = TabAi::new();
    let (tx, mut rx) = oneshot::channel();
    ai.set_approval("cmd-1".into(), tx);
    let generation = ai.cancel_generation();
    assert_eq!(generation, 1);
    assert!(!ai.is_busy());
    // 停止/清空之后，等待中的 Human-in-the-loop 必须按拒绝结算。
    assert_eq!(rx.try_recv(), Ok(false));
    assert!(!ai.answer_approval("cmd-1", true));
}

#[test]
fn local_snapshot_maps_onto_the_ai_snapshot() {
    let mut local = SystemSnapshot::default();
    local.cpu_percent = 91.5;
    local.mem_used_mib = 6 * 1024;
    local.mem_total_mib = 8 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    // (mount, available_bytes, total_bytes) —— 本地快照里是字节，不是 MiB。
    local.disks = vec![("/".into(), 10 * GIB, 100 * GIB)];
    let snap = to_ai_snapshot(&local);
    assert_eq!(snap.cpu_usage_pct, 91.5);
    assert_eq!(snap.mem_total_bytes, 8 * 1024 * 1024 * 1024);
    assert_eq!(snap.disks.len(), 1);
    assert_eq!(snap.disks[0].used_bytes, 90 * GIB);
}

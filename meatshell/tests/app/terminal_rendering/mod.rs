use super::*;

fn hist_line(s: &str) -> Line {
    (s.to_string(), Vec::new(), false)
}

fn wrapped_hist_line(s: &str) -> Line {
    (s.to_string(), Vec::new(), true)
}

fn make_buf(
    rows: u16,
    cols: u16,
    history: &[&str],
    live_lines: &[&str],
    view_offset: usize,
) -> TermBuffer {
    let mut parser = vt100::Parser::new(rows, cols, 0);
    parser.process(live_lines.join("\r\n").as_bytes());
    TermBuffer {
        parser,
        find_query: String::new(),
        is_dark: false,
        output_highlight: OutputHighlightPreset::Log,
        custom_highlight_rules: Vec::new(),
        json_format_output: false,
        vt100_drawing: true,
        charset: crate::terminal::CharsetTracker::default(),
        interactive_echo_until: std::time::Instant::now(),
        sel_anchor: None,
        sel_focus: None,
        sel_ranges: Vec::new(),
        mouse_tracked: false,
        history: history.iter().map(|s| hist_line(s)).collect(),
        prev: Vec::new(),
        view_offset,
        scroll_accum: 0.0,
        displayed_text: Vec::new(),
        csi_state: CsiState::Normal,
        csi_pending: Vec::new(),
        raw: std::collections::VecDeque::new(),
        session_log: None,
        session_log_spec: None,
    }
}

#[test]
fn settings_modal_yields_macos_wheel_to_its_own_scroll_view() {
    assert!(macos_terminal_wheel_can_target_terminal(false));
    assert!(!macos_terminal_wheel_can_target_terminal(true));
}

#[test]
fn releasing_scrollback_drops_retained_history_and_replay_bytes() {
    let mut buffer = make_buf(5, 20, &["old-1", "old-2"], &["live"], 2);
    buffer.prev = vec![hist_line("previous")];
    buffer.raw.extend([1, 2, 3, 4]);
    buffer.displayed_text.push("visible".to_string());
    buffer.sel_anchor = Some((0, 0));
    buffer.sel_focus = Some((1, 1));
    buffer.sel_ranges.push(((0, 0), (1, 1)));

    buffer.release_scrollback();

    assert!(buffer.history.is_empty());
    assert_eq!(buffer.history.capacity(), 0);
    assert!(buffer.prev.is_empty());
    assert_eq!(buffer.prev.capacity(), 0);
    assert!(buffer.raw.is_empty());
    assert_eq!(buffer.raw.capacity(), 0);
    assert!(buffer.displayed_text.is_empty());
    assert!(buffer.sel_anchor.is_none());
    assert!(buffer.sel_focus.is_none());
    assert!(buffer.sel_ranges.is_empty());
    assert_eq!(buffer.view_offset, 0);
}

#[test]
fn scrollback_navigation_keys_only_handle_a_scrolled_normal_screen() {
    let mut buffer = make_buf(
        3,
        20,
        &["old-1", "old-2", "old-3", "old-4", "old-5"],
        &["live"],
        2,
    );

    assert!(handle_scrollback_key(&mut buffer, ScrollbackKey::PageUp));
    assert_eq!(buffer.view_offset, 5);
    assert!(handle_scrollback_key(&mut buffer, ScrollbackKey::PageDown));
    assert_eq!(buffer.view_offset, 2);
    assert!(handle_scrollback_key(&mut buffer, ScrollbackKey::Home));
    assert_eq!(buffer.view_offset, 5);
    assert!(handle_scrollback_key(&mut buffer, ScrollbackKey::End));
    assert_eq!(buffer.view_offset, 0);

    assert!(!handle_scrollback_key(&mut buffer, ScrollbackKey::PageUp));

    buffer.parser.process(b"\x1b[?1049h");
    buffer.view_offset = 1;
    assert!(!handle_scrollback_key(&mut buffer, ScrollbackKey::PageDown));
    assert_eq!(buffer.view_offset, 1);
}

mod charset;
mod colors;
mod protocol;
mod selection;
mod sftp_sorting;

#[test]
fn enabling_session_log_mid_session_seeds_screen_and_keeps_prompt_spacing() {
    let dir = std::env::temp_dir().join(format!("meatshell-log-test-{}", uuid::Uuid::new_v4()));
    let mut buffer = make_buf(5, 40, &[], &[], 0);
    buffer.parser.process(b"line one\r\nuser@host:~$ ");
    buffer.session_log_spec = Some(crate::terminal::SessionLogSpec {
        name: "web".into(),
        target: "ssh root@h:22".into(),
        mode: crate::config::SessionLogMode::Default,
    });

    // Global off: nothing is opened.
    buffer.apply_session_log(false, &dir).unwrap();
    assert!(buffer.session_log.is_none());

    // Turning it on for an open tab starts logging right away.
    buffer.apply_session_log(true, &dir).unwrap();
    let path = buffer.session_log.as_ref().unwrap().path().to_path_buf();
    let _ = buffer.ingest(b"ls\r\n");

    // Turning it off again closes the file.
    buffer.apply_session_log(false, &dir).unwrap();
    assert!(buffer.session_log.is_none());

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.lines().any(|l| l.ends_with("] line one")), "{text}");
    assert!(text.lines().any(|l| l.ends_with("] user@host:~$ ls")), "{text}");
    assert!(text.lines().last().unwrap().starts_with("=== session log closed"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn session_override_off_wins_over_global_on() {
    let dir = std::env::temp_dir().join(format!("meatshell-log-test-{}", uuid::Uuid::new_v4()));
    let mut buffer = make_buf(5, 40, &[], &[], 0);
    buffer.session_log_spec = Some(crate::terminal::SessionLogSpec {
        name: "web".into(),
        target: "local".into(),
        mode: crate::config::SessionLogMode::Off,
    });
    buffer.apply_session_log(true, &dir).unwrap();
    assert!(buffer.session_log.is_none());
    assert!(!dir.exists());
}

/// #490: shrinking the window while an alternate-screen program (nano, vim)
/// runs must not leave the cursor saved by `CSI ? 1049 h` outside the grid,
/// or the first character printed after `CSI ? 1049 l` panics inside vt100.
/// vt100 0.16.2 clamps the saved cursor on resize; keep this when upgrading.
#[test]
fn leaving_alternate_screen_after_shrinking_keeps_cursor_in_bounds() {
    for (start, rows, cols) in [("\x1b[40;1H", 20, 120), ("\x1b[40;100H", 20, 60)] {
        let mut parser = vt100::Parser::new(40, 120, 0);
        parser.process(start.as_bytes());
        parser.process(b"\x1b[?1049h");
        parser.screen_mut().set_size(rows, cols);
        parser.process(b"\x1b[?1049l");
        parser.process("x\u{4e2d}".as_bytes());
        let (row, col) = parser.screen().cursor_position();
        assert!(row < rows && col <= cols, "cursor {row},{col} outside {rows}x{cols}");
    }
}

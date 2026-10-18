//! AI Copilot 抽屉的 Slint 回调接线（FengheShell x rssh 缝合面）。
//!
//! 抽屉本身不长任何业务逻辑：这里只负责把 UI 意图翻译成 ai-copilot 的
//! 输入，并把副作用（写 PTY / 读远端文件）交给 app::ai 的 ToolRuntime。

use super::*;

use ai_copilot::shell::ShellKind;
use ai_copilot::triage::{CopilotConfig, Trigger};

use crate::resource::SystemSnapshot;

/// 抽屉开关：打开 / 关闭某个标签的 AI 抽屉。
fn set_drawer_open(core: &AppCore, window: &Rc<AppWindow>, tab_id: &str, open: bool) {
    set_terminal_row(window, tab_id, |row| row.ai_open = open);
    if !open {
        return;
    }
    // 对话的权威副本在 Rust 侧，换窗口 / 重开抽屉都不会丢，这里刷回去即可。
    resync_conversation(core, &window.as_weak(), tab_id);
    // 「1+1>2」：硬件告警时打开抽屉就顺手起一轮 Triage，不用自己组织问题。
    let Some(ai) = ai_handle(core, tab_id) else {
        return;
    };
    if has_messages(&ai) {
        return;
    }
    let Some(snapshot) = local_snapshot(core) else {
        return;
    };
    let Some(reason) = hot_reason(&snapshot) else {
        return;
    };
    ask_question(core, window, tab_id, String::new(), Trigger::Monitor(reason));
}

/// 最近一次的本地资源快照（与监控侧边栏同源）。
fn local_snapshot(core: &AppCore) -> Option<SystemSnapshot> {
    core.window_states
        .borrow()
        .values()
        .find_map(|w| w.local_snap.lock().ok().map(|s| s.clone()))
}

/// 硬件告警判据：AI 抽屉据此主动发起 Triage。
fn hot_reason(s: &SystemSnapshot) -> Option<String> {
    if s.cpu_percent >= 90.0 {
        return Some(format!("CPU 占用 {:.0}%", s.cpu_percent));
    }
    if s.mem_total_mib > 0 && s.mem_used_mib * 100 / s.mem_total_mib.max(1) >= 90 {
        return Some(format!(
            "内存占用 {}/{} MiB",
            s.mem_used_mib, s.mem_total_mib
        ));
    }
    for (mount, available, total) in &s.disks {
        if *total > 0 && available * 100 / total >= 90 {
            return Some(format!("磁盘 {} 剩余不足 10%", mount));
        }
    }
    None
}

/// 标签所在会话的定义 + 跳板链（供 read_remote_file 走 automation 层）。
fn tab_session(
    core: &AppCore,
    store: &Rc<RefCell<ConfigStore>>,
    tab_id: &str,
) -> Option<(crate::config::Session, Vec<crate::config::Session>)> {
    let session_id = core.tab_routes.lock().ok().and_then(|routes| {
        routes.get(tab_id).and_then(|route| {
            route.lock().ok().and_then(|r| {
                r.statuses
                    .lock()
                    .ok()
                    .and_then(|s| s.get(tab_id).map(|st| st.session_id.clone()))
            })
        })
    })?;
    if session_id.is_empty() {
        return None;
    }
    let store = store.borrow();
    let session = store.get(&session_id)?.clone();
    let jump = store.resolve_jump_chain(&session).unwrap_or_default();
    Some((session, jump))
}

fn shell_kind(session: Option<&crate::config::Session>) -> ShellKind {
    use crate::config::SessionKind;
    match session.map(|s| s.kind) {
        Some(SessionKind::Local) => {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
            ShellKind::from_local_path(&shell)
        }
        Some(SessionKind::Serial) => ShellKind::Serial,
        Some(SessionKind::Telnet) => ShellKind::Telnet,
        _ => ShellKind::Posix,
    }
}

fn endpoint_default(protocol: &str) -> &'static str {
    match protocol {
        "deepseek-thinking" => "https://api.deepseek.com",
        "anthropic-messages" => "https://api.anthropic.com",
        "ollama" => "http://localhost:11434/v1",
        _ => "https://api.openai.com/v1",
    }
}

fn model_default(protocol: &str) -> &'static str {
    match protocol {
        "deepseek-thinking" => "deepseek-chat",
        "anthropic-messages" => "claude-3-5-sonnet-latest",
        "ollama" => "qwen2.5-coder:7b",
        _ => "gpt-4o-mini",
    }
}

fn ai_config(store: &Rc<RefCell<ConfigStore>>, shell: ShellKind) -> CopilotConfig {
    let s = store.borrow();
    let protocol = s.ai_protocol();
    let endpoint = if s.ai_endpoint().trim().is_empty() {
        endpoint_default(protocol).to_string()
    } else {
        s.ai_endpoint().to_string()
    };
    let model = if s.ai_model().trim().is_empty() {
        model_default(protocol).to_string()
    } else {
        s.ai_model().to_string()
    };
    CopilotConfig {
        protocol: protocol.to_string(),
        endpoint,
        api_key: s.ai_api_key().to_string(),
        model,
        shell,
        redaction_enabled: s.ai_redaction_enabled(),
        auto_run_readonly: s.ai_auto_run_readonly(),
        locale: crate::i18n::current_code().to_string(),
        mode: s.ai_mode(),
    }
}

/// 起一轮 Triage。UI 只负责打包上下文，之后全部异步进行。
fn ask_question(
    core: &AppCore,
    win: &AppWindow,
    tab_id: &str,
    question: String,
    trigger: Trigger,
) {
    let Some(ai) = ai_handle(core, tab_id) else {
        return;
    };
    if is_busy(&ai) && matches!(trigger, Trigger::User) {
        push_notice(
            &ai,
            &win.as_weak(),
            tab_id,
            ROLE_ERROR,
            crate::i18n::t("上一次诊断还没结束。", "The previous diagnosis is still running."),
        );
        return;
    }
    let raw = core
        .window_states
        .borrow()
        .values()
        .find(|w| w.terminals_model.iter().any(|r| r.id.as_str() == tab_id))
        .and_then(|w| {
            w.handles
                .borrow()
                .get(tab_id)
                .map(|h| h.commands.clone())
        });
    let store = core.store.clone();
    let (session, jump) = tab_session(core, &store, tab_id)
        .map(|(s, j)| (Some(s), j))
        .unwrap_or((None, Vec::new()));
    let shell = shell_kind(session.as_ref());
    let cfg = ai_config(&store, shell);
    let local = local_snapshot(core);
    spawn_ask(
        core.runtime.handle(),
        AskParams {
            tab_id: tab_id.to_string(),
            question,
            trigger,
            ai,
            weak: win.as_weak(),
            raw,
            session,
            jump,
            cfg,
            shell,
            local,
        },
    );
}

/// 卡片按钮：绿灯→批准执行；橙/红灯→拒绝引擎，同时把命令填进终端让用户自己回车。
fn answer_card(core: &AppCore, tab_id: &str, card_id: &str, approve: bool) {
    let Some(ai) = ai_handle(core, tab_id) else {
        return;
    };
    let Some((gate, cmd)) = card_info(&ai, card_id) else {
        return;
    };
    // 橙/红灯永远只「填入」：Human-in-the-loop 的核心约束。
    let approved = approve && gate == "direct";
    if !approved && gate == "fill" && cmd_has_content(&cmd) {
        if let Some(handle) = core
            .window_states
            .borrow()
            .values()
            .find(|w| w.terminals_model.iter().any(|r| r.id.as_str() == tab_id))
            .and_then(|w| w.handles.borrow().get(tab_id).map(|h| h.commands.clone()))
        {
            let _ = handle.send(crate::ssh::SessionCommand::RawInput(cmd.into_bytes()));
        }
    }
    answer_approval(&ai, card_id, approved);
}

fn cmd_has_content(cmd: &str) -> bool {
    !cmd.trim().is_empty()
}

/// 连通性自检：用本次输入（未填写则回落到已保存配置）请求一次 /models。
/// 不写盘、不改动已保存设置，纯探测。
fn test_connection(
    core: &AppCore,
    win: &Rc<AppWindow>,
    protocol: &str,
    endpoint: &str,
    model: &str,
    api_key: &str,
) {
    let store = core.store.clone();
    // 空白字段回落到已保存配置，这样“只改端点”也能测。
    let cfg = {
        let s = store.borrow();
        (
            s.ai_protocol().to_string(),
            s.ai_endpoint().to_string(),
            s.ai_model().to_string(),
            s.ai_api_key().to_string(),
        )
    };
    let pick = |typed: &str, saved: String| -> String {
        if typed.trim().is_empty() {
            saved
        } else {
            typed.trim().to_string()
        }
    };
    let protocol = pick(protocol, cfg.0);
    let endpoint = pick(endpoint, cfg.1);
    let _model = pick(model, cfg.2);
    let api_key = if api_key.is_empty() { cfg.3 } else { api_key.to_string() };

    win.set_ai_test_status("".into());
    win.set_ai_test_busy(true);
    let weak = win.as_weak();
    core.runtime.spawn(async move {
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            let client = ai_copilot::build_client(&protocol, api_key, endpoint)?;
            let models = client.list_models().await?;
            Ok::<usize, ai_copilot::AppError>(models.len())
        })
        .await;
        // `t()` 只吃 'static 文案，带变量的句子自己按语言拼。
        let text = match outcome {
            Ok(Ok(count)) => {
                if crate::i18n::is_en() {
                    format!("Connected: the endpoint lists {count} models.")
                } else {
                    format!("连接成功：该端点返回 {count} 个可用模型。")
                }
            }
            Ok(Err(e)) => {
                if crate::i18n::is_en() {
                    format!("Connection failed: {e}")
                } else {
                    format!("连接失败：{e}")
                }
            }
            Err(_) => crate::i18n::t("连接超时（20 秒）。", "Timed out after 20 s.").to_string(),
        };
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(win) = weak.upgrade() {
                win.set_ai_test_status(text.into());
                win.set_ai_test_busy(false);
            }
        });
    });
}

/// 空会话时的起手建议：对应 Copilot 的 starter suggestions，
/// 都是「先只读、不落地改动」的排障问法。
fn starter_questions() -> Vec<SharedString> {
    let en = crate::i18n::is_en();
    [
        (
            "这台机器为什么卡？先看 CPU、内存和负载",
            "Why is this box slow? Check CPU, memory and load first",
        ),
        (
            "看看 /var/log 里最新的错误，只做只读排查",
            "Show the latest errors in /var/log - read-only investigation",
        ),
        (
            "磁盘快满了，帮我找出最大的目录",
            "Disk is almost full - find the largest directories",
        ),
    ]
    .iter()
    .map(|(zh, en_s)| SharedString::from(if en { *en_s } else { *zh }))
    .collect()
}

pub(super) fn wire_ai(ctx: &WinCtx) {
    let WinCtx { core, store, window, .. } = ctx;

    window.set_ai_starters(ModelRc::from(std::rc::Rc::new(VecModel::from(
        starter_questions(),
    ))));

    // --- 播种 LLM 设置 ---------------------------------------------------
    {
        let s = store.borrow();
        window.set_ai_protocol(s.ai_protocol().into());
        window.set_ai_endpoint(s.ai_endpoint().into());
        window.set_ai_model(s.ai_model().into());
        window.set_ai_redaction_enabled(s.ai_redaction_enabled());
        window.set_ai_auto_run_readonly(s.ai_auto_run_readonly());
        window.set_ai_mode(s.ai_mode().as_str().into());
    }

    // --- 工作方式（Ask / Agent）------------------------------------------
    {
        let core = core.clone();
        let store = store.clone();
        let win = window.clone();
        window.on_ai_set_mode(move |mode: SharedString| {
            let mode = ai_copilot::triage::CopilotMode::parse(mode.as_str());
            {
                let mut s = store.borrow_mut();
                s.set_ai_mode(mode);
                let _ = s.save();
            }
            // 所有窗口共享同一份设置。
            core.registry.for_each(|weak| {
                if let Some(w) = weak.upgrade() {
                    w.set_ai_mode(mode.as_str().into());
                }
            });
            win.set_ai_mode(mode.as_str().into());
        });
    }

    // --- 抽屉开关 --------------------------------------------------------
    {
        let core = core.clone();
        let win = window.clone();
        window.on_ai_toggle(move |tab_id: SharedString| {
            let open = ai_drawer_open(&core, &tab_id);
            set_drawer_open(&core, &win, &tab_id, !open);
        });
    }
    {
        let core = core.clone();
        let win = window.clone();
        window.on_ai_close(move |tab_id: SharedString| {
            set_drawer_open(&core, &win, &tab_id, false);
        });
    }

    // --- 提问 / 清空 / 停止 ----------------------------------------------
    {
        let core = core.clone();
        window.on_ai_send(move |tab_id: SharedString, question: SharedString| {
            let Some(win) = window_for_tab(&core, &tab_id) else {
                return;
            };
            ask_question(&core, &win, &tab_id, question.to_string(), Trigger::User);
        });
    }
    {
        let core = core.clone();
        window.on_ai_clear(move |tab_id: SharedString| {
            let Some(ai) = ai_handle(&core, &tab_id) else {
                return;
            };
            if let Some(win) = window_for_tab(&core, &tab_id) {
                clear_conversation(&ai, &win.as_weak(), &tab_id);
            }
        });
    }
    {
        let core = core.clone();
        window.on_ai_cancel(move |tab_id: SharedString| {
            // 停止不等同于中止 LLM 请求（请求会自己跑完），但会立刻作废它的
            // UI 写入并结清等待中的审批。
            let Some(ai) = ai_handle(&core, &tab_id) else {
                return;
            };
            cancel_generation(&ai);
        });
    }

    // --- Run Gate：执行 / 填入 / 拒绝 -------------------------------------
    {
        let core = core.clone();
        window.on_ai_run_card(move |tab_id: SharedString, card_id: SharedString| {
            answer_card(&core, &tab_id, &card_id, true);
        });
    }
    {
        let core = core.clone();
        window.on_ai_reject_card(move |tab_id: SharedString, card_id: SharedString| {
            answer_card(&core, &tab_id, &card_id, false);
        });
    }

    // --- 连通性自检 --------------------------------------------------------
    {
        let core = core.clone();
        let win = window.clone();
        let win_owned = win.clone();
        win.on_ai_test_connection(
            move |protocol: SharedString,
                  endpoint: SharedString,
                  model: SharedString,
                  api_key: SharedString| {
                test_connection(
                    &core,
                    &win_owned,
                    &protocol,
                    &endpoint,
                    &model,
                    &api_key,
                );
            },
        );
    }

    // --- 设置保存 ----------------------------------------------------------
    {
        let core = core.clone();
        let store = store.clone();
        window.on_ai_apply_settings(move |
            protocol: SharedString,
            endpoint: SharedString,
            model: SharedString,
            api_key: SharedString,
            redaction: bool,
            auto_run: bool,
        | {
            {
                let mut s = store.borrow_mut();
                s.set_ai_settings(
                    protocol.to_string(),
                    endpoint.to_string(),
                    model.to_string(),
                    api_key.to_string(),
                    redaction,
                    auto_run,
                );
                let _ = s.save();
            }
            let s = store.borrow();
            // 所有窗口共享同一份 LLM 设置，改一处要立刻同步到每个实例。
            core.registry.for_each(|weak| {
                if let Some(win) = weak.upgrade() {
                    win.set_ai_protocol(s.ai_protocol().into());
                    win.set_ai_endpoint(s.ai_endpoint().into());
                    win.set_ai_model(s.ai_model().into());
                    win.set_ai_redaction_enabled(s.ai_redaction_enabled());
                    win.set_ai_auto_run_readonly(s.ai_auto_run_readonly());
                }
            });
        });
    }
}

/// 抽屉当前是否打开。
fn ai_drawer_open(core: &AppCore, tab_id: &str) -> bool {
    window_for_tab(core, tab_id)
        .and_then(|win| {
            let model = win.get_terminals();
            let Some(rows) = model.as_any().downcast_ref::<slint::VecModel<TerminalState>>() else {
                return None;
            };
            rows.iter().find(|r| r.id.as_str() == tab_id).map(|r| r.ai_open)
        })
        .unwrap_or(false)
}

/// 找到承载该标签的那个窗口。
fn window_for_tab(core: &AppCore, tab_id: &str) -> Option<Rc<AppWindow>> {
    core.window_states
        .borrow()
        .values()
        .find(|w| {
            w.terminals_model
                .iter()
                .any(|r| r.id.as_str() == tab_id)
        })
        .map(|w| w.main_win.clone())
}

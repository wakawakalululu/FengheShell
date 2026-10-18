#[cfg(test)]
#[path = "../../tests/app/window_management/launch_intent.rs"]
mod launch_intent_tests;

/// What this process launch is supposed to do, parsed from argv before any
/// window exists. `--new-window` is issued by the OS entry points (Windows
/// jump list, macOS dock menu, Linux desktop action); when an instance is
/// already running it is forwarded over the single-instance socket instead
/// of opening a second process.
pub struct LaunchIntent {
    // Parsed from argv and asserted by tests; run() opens windows itself, so
    // the flag has no reader until the new-window flow is wired up.
    #[allow(dead_code)]
    pub new_window: bool,
}

pub fn parse(args: &[String]) -> LaunchIntent {
    LaunchIntent {
        new_window: args.iter().any(|a| a == "--new-window"),
    }
}

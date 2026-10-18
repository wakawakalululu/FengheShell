use crate::app::launch::parse;

#[test]
fn no_flags_means_plain_launch() {
    let intent = parse(&["fengheshell".to_string()]);
    assert!(!intent.new_window);
}

#[test]
fn new_window_flag_is_recognised() {
    let intent = parse(&["fengheshell".to_string(), "--new-window".to_string()]);
    assert!(intent.new_window);
}

#[test]
fn unrelated_args_do_not_trigger_new_window() {
    let intent = parse(&["fengheshell".to_string(), "--version".to_string()]);
    assert!(!intent.new_window);
}

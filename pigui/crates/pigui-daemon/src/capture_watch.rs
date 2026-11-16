use std::sync::Arc;
use std::time::Duration;

use pigui_core::rpc::CaptureState;

use crate::api;
use crate::state::AppState;

const POLL_INTERVAL: Duration = Duration::from_secs(3);
const STABLE_POLLS: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
enum InterfaceAction {
    None,
    Switch(String),
    Start(String),
}

fn decide_interface_action(
    capture: Option<&CaptureState>,
    last_default: Option<&str>,
    new_default: Option<&str>,
    pinned: bool,
    suppressed: bool,
    was_capturing: bool,
) -> InterfaceAction {
    let Some(new_default) = new_default.filter(|value| !value.is_empty()) else {
        return InterfaceAction::None;
    };
    let Some(last_default) = last_default.filter(|value| !value.is_empty()) else {
        return InterfaceAction::None;
    };
    if new_default == last_default || pinned {
        return InterfaceAction::None;
    }
    match capture {
        Some(capture) if capture.interface == last_default => {
            InterfaceAction::Switch(new_default.to_string())
        }
        Some(_) => InterfaceAction::None,
        None if was_capturing && !suppressed => InterfaceAction::Start(new_default.to_string()),
        None => InterfaceAction::None,
    }
}

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut last_default = current_default_interface().await;
        let mut was_capturing = state.capture().is_some();
        let mut candidate: Option<String> = None;
        let mut stable_polls = 0u32;

        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            let Some(new_default) = current_default_interface().await else {
                candidate = None;
                stable_polls = 0;
                continue;
            };
            if state.capture().is_some() {
                was_capturing = true;
            }
            if last_default.as_deref() == Some(new_default.as_str()) {
                candidate = None;
                stable_polls = 0;
                continue;
            }
            if candidate.as_deref() == Some(new_default.as_str()) {
                stable_polls += 1;
            } else {
                candidate = Some(new_default.clone());
                stable_polls = 1;
            }
            if stable_polls < STABLE_POLLS {
                continue;
            }

            let action = decide_interface_action(
                state.capture().as_ref(),
                last_default.as_deref(),
                Some(new_default.as_str()),
                state.config.snort_interface.is_some(),
                state.capture_suppressed(),
                was_capturing,
            );
            if action == InterfaceAction::None {
                tracing::info!(
                    previous = last_default.as_deref().unwrap_or("none"),
                    current = %new_default,
                    "default route changed; capture left unchanged"
                );
                last_default = Some(new_default);
                candidate = None;
                stable_polls = 0;
                continue;
            }

            let Ok(_guard) = state.capture_lock.try_lock() else {
                continue;
            };

            let action = decide_interface_action(
                state.capture().as_ref(),
                last_default.as_deref(),
                Some(new_default.as_str()),
                state.config.snort_interface.is_some(),
                state.capture_suppressed(),
                was_capturing,
            );
            if action == InterfaceAction::None {
                last_default = Some(new_default);
                candidate = None;
                stable_polls = 0;
                continue;
            }

            let result = match &action {
                InterfaceAction::Switch(interface) => {
                    tracing::info!(
                        from = last_default.as_deref().unwrap_or("none"),
                        to = %interface,
                        "capture watcher switching interface"
                    );
                    api::capture_switch_locked(&state, interface).await
                }
                InterfaceAction::Start(interface) => {
                    tracing::info!(
                        interface = %interface,
                        "capture watcher restarting capture after route change"
                    );
                    api::capture_start_locked(&state, interface).await
                }
                InterfaceAction::None => unreachable!(),
            };

            match result {
                Ok(capture) => {
                    tracing::info!(
                        interface = %capture.interface,
                        "capture watcher updated capture interface"
                    );
                    last_default = Some(new_default);
                    was_capturing = true;
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        interface = %new_default,
                        "capture watcher could not update capture interface"
                    );
                }
            }
            candidate = None;
            stable_polls = 0;
        }
    });
}

async fn current_default_interface() -> Option<String> {
    tokio::task::spawn_blocking(pigui_collector::default_interface)
        .await
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(interface: &str) -> CaptureState {
        CaptureState {
            interface: interface.to_string(),
            snort_pid: None,
            log_dir: String::new(),
            mode: "dev-helper".to_string(),
            started_at: 0,
        }
    }

    #[test]
    fn follows_a_stable_route_change_from_the_old_default() {
        let action = decide_interface_action(
            Some(&capture("utun6")),
            Some("utun6"),
            Some("en0"),
            false,
            false,
            true,
        );
        assert_eq!(action, InterfaceAction::Switch("en0".to_string()));
    }

    #[test]
    fn restarts_capture_after_it_dropped_during_a_route_change() {
        let action = decide_interface_action(None, Some("utun6"), Some("en0"), false, false, true);
        assert_eq!(action, InterfaceAction::Start("en0".to_string()));
    }

    #[test]
    fn respects_an_explicit_user_stop() {
        let action = decide_interface_action(None, Some("utun6"), Some("en0"), false, true, true);
        assert_eq!(action, InterfaceAction::None);
    }

    #[test]
    fn leaves_a_manual_non_default_interface_alone() {
        let action = decide_interface_action(
            Some(&capture("en0")),
            Some("utun6"),
            Some("utun7"),
            false,
            false,
            true,
        );
        assert_eq!(action, InterfaceAction::None);
    }

    #[test]
    fn pinned_interfaces_never_switch() {
        let action = decide_interface_action(
            Some(&capture("utun6")),
            Some("utun6"),
            Some("en0"),
            true,
            false,
            true,
        );
        assert_eq!(action, InterfaceAction::None);
    }

    #[test]
    fn matching_or_missing_routes_are_noops() {
        assert_eq!(
            decide_interface_action(
                Some(&capture("en0")),
                Some("en0"),
                Some("en0"),
                false,
                false,
                true,
            ),
            InterfaceAction::None
        );
        assert_eq!(
            decide_interface_action(Some(&capture("en0")), Some("en0"), None, false, false, true,),
            InterfaceAction::None
        );
        assert_eq!(
            decide_interface_action(
                Some(&capture("en0")),
                None,
                Some("utun6"),
                false,
                false,
                true,
            ),
            InterfaceAction::None
        );
    }
}

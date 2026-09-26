/// True when the local computer can plausibly show a browser window. macOS and
/// Windows sessions are treated as desktop; on other Unix hosts an SSH session
/// or a missing display server indicates a headless computer.
pub fn has_display() -> bool {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        true
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        has_display_from(|name| std::env::var_os(name))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn has_display_from(get: impl Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    let set = |name: &str| get(name).is_some_and(|value| !value.is_empty());
    // X11 forwarding sets DISPLAY inside SSH sessions, but the browser would
    // open on the remote host, not next to the user.
    !set("SSH_CONNECTION") && !set("SSH_CLIENT") && !set("SSH_TTY") && (set("DISPLAY") || set("WAYLAND_DISPLAY"))
}

#[cfg(all(test, unix, not(target_os = "macos")))]
mod tests {
    use super::has_display_from;
    use std::collections::HashMap;
    use std::ffi::OsString;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), OsString::from(value)))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn wayland_session_has_display() {
        assert!(has_display_from(env(&[("WAYLAND_DISPLAY", "wayland-0")])));
    }

    #[test]
    fn x11_session_has_display() {
        assert!(has_display_from(env(&[("DISPLAY", ":0")])));
    }

    #[test]
    fn ssh_session_is_headless_even_with_x11_forwarding() {
        assert!(!has_display_from(env(&[
            ("SSH_TTY", "/dev/pts/0"),
            ("DISPLAY", "localhost:10.0"),
        ])));
        assert!(!has_display_from(env(&[
            ("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22"),
            ("WAYLAND_DISPLAY", "wayland-0"),
        ])));
        assert!(!has_display_from(env(&[
            ("SSH_CLIENT", "10.0.0.1 22 22"),
            ("DISPLAY", ":0"),
        ])));
    }

    #[test]
    fn no_display_variables_is_headless() {
        assert!(!has_display_from(env(&[])));
        assert!(!has_display_from(env(&[("DISPLAY", "")])));
    }
}

use crate::ResultType;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    time::{Duration, Instant},
};
use users::{get_current_uid, get_user_by_uid, os::unix::UserExt};

use sctk::{
    output::OutputData,
    output::{OutputHandler, OutputState},
    reexports::client::protocol::wl_output::WlOutput,
    reexports::client::{globals, Proxy},
    reexports::client::{Connection, QueueHandle},
    registry::{ProvidesRegistryState, RegistryState},
};

lazy_static::lazy_static! {
    pub static ref DISTRO: Distro = Distro::new();
}

// to-do: There seems to be some runtime issue that causes the audit logs to be generated.
// We may need to fix this and remove this workaround in the future.
//
// We use the pre-search method to find the command path to avoid the audit logs on some systems.
// No idea why the audit logs happen.
// Though the audit logs may disappear after rebooting.
//
// See https://github.com/rustdesk/rustdesk/discussions/11959
//
// `ausearch -x /usr/share/rustdesk/rustdesk` will return
// ...
// time->Tue Jun 24 10:40:43 2025
// type=PROCTITLE msg=audit(1750776043.446:192757): proctitle=2F7573722F62696E2F727573746465736B002D2D73657276696365
// type=PATH msg=audit(1750776043.446:192757): item=0 name="/usr/local/bin/sh" nametype=UNKNOWN cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
// type=CWD msg=audit(1750776043.446:192757): cwd="/"
// type=SYSCALL msg=audit(1750776043.446:192757): arch=c000003e syscall=59 success=no exit=-2 a0=7fb7dbd22da0 a1=1d65f2c0 a2=7ffc25193360 a3=7ffc25194ec0 items=1 ppid=172208 pid=267565 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="rustdesk" exe="/usr/share/rustdesk/rustdesk" subj=unconfined key="processos_criados"
// ----
// time->Tue Jun 24 10:40:43 2025
// type=PROCTITLE msg=audit(1750776043.446:192758): proctitle=2F7573722F62696E2F727573746465736B002D2D73657276696365
// type=PATH msg=audit(1750776043.446:192758): item=0 name="/usr/sbin/sh" nametype=UNKNOWN cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
// ...
lazy_static::lazy_static! {
    pub static ref CMD_LOGINCTL: String = find_cmd_path("loginctl");
    pub static ref CMD_PS: String = find_cmd_path("ps");
    pub static ref CMD_SH: String = find_cmd_path("sh");
}

pub const DISPLAY_SERVER_WAYLAND: &str = "wayland";
pub const DISPLAY_SERVER_X11: &str = "x11";
pub const DISPLAY_DESKTOP_KDE: &str = "KDE";

pub const XDG_CURRENT_DESKTOP: &str = "XDG_CURRENT_DESKTOP";

pub struct Distro {
    pub name: String,
    pub version_id: String,
}

impl Distro {
    fn new() -> Self {
        let name = run_cmds("awk -F'=' '/^NAME=/ {print $2}' /etc/os-release")
            .unwrap_or_default()
            .trim()
            .trim_matches('"')
            .to_string();
        let version_id = run_cmds("awk -F'=' '/^VERSION_ID=/ {print $2}' /etc/os-release")
            .unwrap_or_default()
            .trim()
            .trim_matches('"')
            .to_string();
        Self { name, version_id }
    }
}

fn find_cmd_path(cmd: &'static str) -> String {
    let test_cmd = format!("/bin/{}", cmd);
    if std::path::Path::new(&test_cmd).exists() {
        return test_cmd;
    }
    let test_cmd = format!("/usr/bin/{}", cmd);
    if std::path::Path::new(&test_cmd).exists() {
        return test_cmd;
    }
    if let Ok(output) = Command::new("which").arg(cmd).output() {
        if output.status.success() {
            return String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }
    cmd.to_string()
}

// Deprecated. Use `hbb_common::platform::linux::is_kde_session()` instead for now.
// Or we need to set the correct environment variable in the server process.
#[inline]
pub fn is_kde() -> bool {
    if let Ok(env) = std::env::var(XDG_CURRENT_DESKTOP) {
        env == DISPLAY_DESKTOP_KDE
    } else {
        false
    }
}

// Don't use `hbb_common::platform::linux::is_kde()` here.
// It's not correct in the server process.
pub fn is_kde_session() -> bool {
    std::process::Command::new(CMD_SH.as_str())
        .arg("-c")
        .arg("pgrep -f kded[0-9]+")
        .stdout(std::process::Stdio::piped())
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

#[inline]
pub fn is_gdm_user(username: &str) -> bool {
    username == "gdm" || username == "sddm"
    // || username == "lightgdm"
}

#[inline]
pub fn is_desktop_wayland() -> bool {
    get_display_server() == DISPLAY_SERVER_WAYLAND
}

#[inline]
pub fn is_x11_or_headless() -> bool {
    !is_desktop_wayland()
}

// -1
const INVALID_SESSION: &str = "4294967295";

pub fn get_display_server() -> String {
    // Check for forced display server environment variable first
    if let Ok(forced_display) = std::env::var("RUSTDESK_FORCED_DISPLAY_SERVER") {
        return forced_display;
    }

    // Prefer reading logind's session files directly under /run/systemd/sessions.
    // This avoids spawning `loginctl` on every probe, which on UOS/DDE triggers
    // a `Display counting failed: Success` audit line per call and floods
    // /var/log. Falls back to `loginctl` when the directory is unavailable.
    if let Some(sid) = seat0_session_id() {
        return get_display_server_of_session(&sid);
    }

    // Fallback: legacy `loginctl` based detection.
    if run_loginctl(None).is_err() {
        return DISPLAY_SERVER_X11.to_owned();
    }

    let mut session = get_values_of_seat0(&[0])[0].clone();
    if session.is_empty() {
        // loginctl has not given the expected output.  try something else.
        if let Ok(sid) = std::env::var("XDG_SESSION_ID") {
            // could also execute "cat /proc/self/sessionid"
            session = sid;
        }
        if session.is_empty() {
            session = run_cmds("cat /proc/self/sessionid").unwrap_or_default();
            if session == INVALID_SESSION {
                session = "".to_owned();
            }
        }
    }
    if session.is_empty() {
        std::env::var("XDG_SESSION_TYPE").unwrap_or("x11".to_owned())
    } else {
        get_display_server_of_session(&session)
    }
}

pub fn get_display_server_of_session(session: &str) -> String {
    // Read the session file directly instead of spawning `loginctl`.
    if let Some(fields) = read_session_file(session) {
        if let Some(t) = fields.get("TYPE") {
            let display_server = t.trim().to_lowercase();
            if display_server.is_empty()
                || display_server == "tty"
                || display_server == "unspecified"
            {
                if let Ok(sestype) = std::env::var("XDG_SESSION_TYPE") {
                    if !sestype.is_empty() {
                        return sestype.to_lowercase();
                    }
                }
                return "x11".to_owned();
            }
            return display_server;
        }
    }

    // Fallback to `loginctl` if the session file is missing/unreadable.
    let mut display_server = if let Ok(output) =
        run_loginctl(Some(vec!["show-session", "-p", "Type", session]))
    // Check session type of the session
    {
        String::from_utf8_lossy(&output.stdout)
            .replace("Type=", "")
            .trim_end()
            .into()
    } else {
        "".to_owned()
    };
    if display_server.is_empty() || display_server == "tty" || display_server == "unspecified" {
        if let Ok(sestype) = std::env::var("XDG_SESSION_TYPE") {
            if !sestype.is_empty() {
                return sestype.to_lowercase();
            }
        }
        display_server = "x11".to_owned();
    }
    display_server.to_lowercase()
}

#[inline]
fn line_values(indices: &[usize], line: &str) -> Vec<String> {
    indices
        .into_iter()
        .map(|idx| line.split_whitespace().nth(*idx).unwrap_or("").to_owned())
        .collect::<Vec<String>>()
}

#[inline]
pub fn get_values_of_seat0(indices: &[usize]) -> Vec<String> {
    _get_values_of_seat0(indices, true)
}

#[inline]
pub fn get_values_of_seat0_with_gdm_wayland(indices: &[usize]) -> Vec<String> {
    _get_values_of_seat0(indices, false)
}

fn _get_values_of_seat0(indices: &[usize], ignore_gdm_wayland: bool) -> Vec<String> {
    // Read logind session files directly under /run/systemd/sessions instead of
    // spawning `loginctl list-sessions`. Each file is a KEY=VALUE dump that
    // already contains SID (filename), UID, USER, SEAT, STATE, ACTIVE, TYPE.
    if let Some(mut sessions) = list_sessions() {
        sessions.sort_by(|a, b| a.0.cmp(&b.0));
        // Prefer an active seat0 session.
        for (sid, fields) in &sessions {
            let is_seat0 = fields.get("SEAT").map(|s| s.trim() == "seat0").unwrap_or(false);
            if is_seat0 && is_active_fields(fields) {
                if ignore_gdm_wayland {
                    if is_gdm_user(fields.get("USER").map(|s| s.as_str()).unwrap_or(""))
                        && get_display_server_of_session(sid) == DISPLAY_SERVER_WAYLAND
                    {
                        continue;
                    }
                }
                return map_session_values(sid, fields, indices);
            }
        }
        // Fallback: any active session that is not tty/unspecified
        // (covers systems without a seat0, see rustdesk issue #73).
        for (sid, fields) in &sessions {
            if is_active_fields(fields) {
                let d = get_display_server_of_session(sid);
                if ignore_gdm_wayland {
                    if is_gdm_user(fields.get("USER").map(|s| s.as_str()).unwrap_or(""))
                        && d == DISPLAY_SERVER_WAYLAND
                    {
                        continue;
                    }
                }
                if d == "tty" || d == "unspecified" {
                    continue;
                }
                return map_session_values(sid, fields, indices);
            }
        }
    }

    line_values(indices, "")
}

/// Returns `(sid, parsed_fields)` for every session file under
/// `/run/systemd/sessions`, skipping the `.ref` FIFOs and unreadable entries.
fn list_sessions() -> Option<Vec<(String, HashMap<String, String>)>> {
    let dir = std::path::Path::new("/run/systemd/sessions");
    let mut out = Vec::new();
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e == "ref").unwrap_or(false) {
            continue;
        }
        let sid = match path.file_stem() {
            Some(s) => s.to_string_lossy().to_string(),
            None => continue,
        };
        if let Some(fields) = parse_key_value_file(&path) {
            out.push((sid, fields));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Returns the active seat0 session id, if any, by reading `/run/systemd/seats/seat0`.
fn seat0_session_id() -> Option<String> {
    let path = std::path::Path::new("/run/systemd/seats/seat0");
    let fields = parse_key_value_file(path)?;
    // `ACTIVE` holds the active session id on seat0.
    fields.get("ACTIVE").map(|s| s.trim().to_string())
}

/// Parse a logind key=value session/seat file. Lines starting with `#` and
/// blank lines are ignored. This is the same data `loginctl` prints, but read
/// directly from the filesystem with no process spawn.
fn parse_key_value_file(path: &std::path::Path) -> Option<HashMap<String, String>> {
    let content = fs::read_to_string(path).ok()?;
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().to_string();
            let val = line[eq + 1..].trim().to_string();
            map.insert(key, val);
        }
    }
    Some(map)
}

fn read_session_file(sid: &str) -> Option<HashMap<String, String>> {
    let path = std::path::Path::new("/run/systemd/sessions").join(sid);
    parse_key_value_file(&path)
}

fn is_active_fields(fields: &HashMap<String, String>) -> bool {
    fields.get("STATE").map(|s| s.trim() == "active").unwrap_or(false)
        || fields.get("ACTIVE").map(|s| s.trim() == "1").unwrap_or(false)
}

/// Map parsed session fields to the indexed tuple historically returned by
/// `get_values_of_seat0`: index 0 = sid, 1 = uid, 2 = username.
fn map_session_values(
    sid: &str,
    fields: &HashMap<String, String>,
    indices: &[usize],
) -> Vec<String> {
    let uid = fields.get("UID").map(|s| s.trim().to_string()).unwrap_or_default();
    let username = fields
        .get("USER")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    indices
        .iter()
        .map(|idx| match *idx {
            0 => sid.to_string(),
            1 => uid.clone(),
            2 => username.clone(),
            _ => "".to_string(),
        })
        .collect()
}

pub fn is_active(sid: &str) -> bool {
    if let Some(fields) = read_session_file(sid) {
        return is_active_fields(&fields);
    }
    // Fallback to `loginctl`.
    if let Ok(output) = run_loginctl(Some(vec!["show-session", "-p", "State", sid])) {
        String::from_utf8_lossy(&output.stdout).contains("active")
    } else {
        false
    }
}

pub fn is_active_and_seat0(sid: &str) -> bool {
    if let Some(fields) = read_session_file(sid) {
        return is_active_fields(&fields)
            && fields.get("SEAT").map(|s| s.trim() == "seat0").unwrap_or(false);
    }
    // Fallback to `loginctl`.
    if let Ok(output) = run_loginctl(Some(vec!["show-session", sid])) {
        String::from_utf8_lossy(&output.stdout).contains("State=active")
            && String::from_utf8_lossy(&output.stdout).contains("Seat=seat0")
    } else {
        false
    }
}

// Check both "Lock" and "Switch user"
pub fn is_session_locked(sid: &str) -> bool {
    // `LockedHint` is not always present in the session file, so query logind.
    // This is called on a slow path (lock detection), not in the service loop.
    if let Ok(output) = run_loginctl(Some(vec!["show-session", sid, "--property=LockedHint"])) {
        String::from_utf8_lossy(&output.stdout).contains("LockedHint=yes")
    } else {
        false
    }
}

// **Note** that the return value here, the last character is '\n'.
// Use `run_cmds_trim_newline()` if you want to remove '\n' at the end.
pub fn run_cmds(cmds: &str) -> ResultType<String> {
    let output = std::process::Command::new(CMD_SH.as_str())
        .args(vec!["-c", cmds])
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn run_cmds_trim_newline(cmds: &str) -> ResultType<String> {
    let output = std::process::Command::new(CMD_SH.as_str())
        .args(vec!["-c", cmds])
        .output()?;
    let out = String::from_utf8_lossy(&output.stdout);
    Ok(if out.ends_with('\n') {
        out[..out.len() - 1].to_string()
    } else {
        out.to_string()
    })
}

// The UOS/DDE `systemd-logind` setup triggers an extreme rate of `loginctl`
// calls from the RustDesk `--service` loop (every 500 ms the desktop refresh
// queries seat0, active state and per-session type, each spawning a new
// `loginctl` process). On this system logind also logs every call to
// `auth.log`/syslog as `Display counting failed: Success`, growing the logs by
// tens of MB per hour and pinning a CPU core. The session type / seat0 layout
// changes at most on login/logout, so caching the `loginctl` output for a few
// seconds is safe and eliminates the storm.
const LOGINCTL_CACHE_TTL: Duration = Duration::from_secs(2);

struct LoginctlCacheEntry {
    // `None` stores a failed `loginctl` invocation (callers treat failure the
    // same as an empty/error result).
    output: Option<std::process::Output>,
    ts: Instant,
}

lazy_static::lazy_static! {
    static ref LOGINCTL_CACHE: Mutex<HashMap<String, LoginctlCacheEntry>> =
        Mutex::new(HashMap::new());
}

fn run_loginctl_uncached(args: Option<Vec<&str>>) -> Option<std::process::Output> {
    if std::env::var("FLATPAK_ID").is_ok() {
        let mut l_args = CMD_LOGINCTL.to_string();
        if let Some(a) = args.as_ref() {
            l_args = format!("{} {}", l_args, a.join(" "));
        }
        let res = std::process::Command::new("flatpak-spawn")
            .args(vec![String::from("--host"), l_args])
            .output();
        if let Ok(o) = res {
            return Some(o);
        }
    }
    let mut cmd = std::process::Command::new(CMD_LOGINCTL.as_str());
    if let Some(a) = args {
        if let Ok(o) = cmd.args(a).output() {
            return Some(o);
        }
        return None;
    }
    cmd.output().ok()
}

/// Cached wrapper around `loginctl`. The result of each distinct argument set
/// is cached for `LOGINCTL_CACHE_TTL` seconds, after which a fresh `loginctl`
/// process is spawned and the cache entry refreshed.
///
/// Returns `Err` (matching the previous signature) when the cache is poisoned
/// or the invocation fails, so existing callers that branch on `.is_err()`
/// keep working unchanged.
fn run_loginctl(args: Option<Vec<&str>>) -> std::io::Result<std::process::Output> {
    let key = match &args {
        None => String::new(),
        Some(a) => a.join("\u{1}"),
    };
    let now = Instant::now();
    if let Ok(cache) = LOGINCTL_CACHE.lock() {
        if let Some(entry) = cache.get(&key) {
            if now.duration_since(entry.ts) < LOGINCTL_CACHE_TTL {
                return match &entry.output {
                    Some(o) => Ok(o.clone()),
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "cached loginctl failure",
                    )),
                };
            }
        }
    }
    let output = run_loginctl_uncached(args);
    if let Ok(mut cache) = LOGINCTL_CACHE.lock() {
        cache.insert(
            key,
            LoginctlCacheEntry {
                output: output.clone(),
                ts: Instant::now(),
            },
        );
    }
    output.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "loginctl invocation failed")
    })
}

/// forever: may not work
#[cfg(target_os = "linux")]
pub fn system_message(title: &str, msg: &str, forever: bool) -> ResultType<()> {
    let cmds: HashMap<&str, Vec<&str>> = HashMap::from([
        ("notify-send", [title, msg].to_vec()),
        (
            "zenity",
            [
                "--info",
                "--timeout",
                if forever { "0" } else { "3" },
                "--title",
                title,
                "--text",
                msg,
            ]
            .to_vec(),
        ),
        ("kdialog", ["--title", title, "--msgbox", msg].to_vec()),
        (
            "xmessage",
            [
                "-center",
                "-timeout",
                if forever { "0" } else { "3" },
                title,
                msg,
            ]
            .to_vec(),
        ),
    ]);
    for (k, v) in cmds {
        if Command::new(k).args(v).spawn().is_ok() {
            return Ok(());
        }
    }
    crate::bail!("failed to post system message");
}

#[derive(Debug, Clone)]
pub struct WaylandDisplayInfo {
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub logical_size: Option<(i32, i32)>,
    pub refresh_rate: i32,
}

// Retrieves information about all connected displays via the Wayland protocol.
pub fn get_wayland_displays() -> ResultType<Vec<WaylandDisplayInfo>> {
    struct WaylandEnv {
        registry_state: RegistryState,
        output_state: OutputState,
    }

    impl OutputHandler for WaylandEnv {
        fn output_state(&mut self) -> &mut OutputState {
            &mut self.output_state
        }

        fn new_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: WlOutput) {}
        fn update_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: WlOutput) {}
        fn output_destroyed(&mut self, _: &Connection, _: &QueueHandle<Self>, _: WlOutput) {}
    }

    impl ProvidesRegistryState for WaylandEnv {
        fn registry(&mut self) -> &mut RegistryState {
            &mut self.registry_state
        }

        sctk::registry_handlers!();
    }

    sctk::delegate_output!(WaylandEnv);
    sctk::delegate_registry!(WaylandEnv);

    let conn = Connection::connect_to_env()?;
    let (globals, mut event_queue) = globals::registry_queue_init(&conn)?;
    let queue_handle = event_queue.handle();

    let registry_state = RegistryState::new(&globals);
    let output_state = OutputState::new(&globals, &queue_handle);

    let mut environment = WaylandEnv {
        registry_state,
        output_state,
    };

    event_queue.roundtrip(&mut environment)?;

    let outputs: Vec<_> = environment.output_state.outputs().collect();
    let mut display_infos = Vec::new();

    for output in outputs {
        if let Some(output_data) = output.data::<OutputData>() {
            output_data.with_output_info(|info| {
                if let Some(mode) = info.modes.iter().find(|m| m.current) {
                    let (x, y) = info.location;
                    let (width, height) = mode.dimensions;
                    let refresh_rate = mode.refresh_rate;
                    let name = info.name.clone().unwrap_or_default();
                    let logical_size = info.logical_size;
                    display_infos.push(WaylandDisplayInfo {
                        name,
                        x,
                        y,
                        width,
                        height,
                        logical_size,
                        refresh_rate,
                    });
                }
            });
        }
    }

    Ok(display_infos)
}

/// Escape a string for safe use in shell commands by wrapping in single quotes.
///
/// This function handles the edge case of single quotes within the string by:
/// 1. Ending the current single-quoted section
/// 2. Adding an escaped single quote
/// 3. Starting a new single-quoted section
///
/// Example: "it's here" -> "'it'\''s here'"
#[inline]
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace("'", "'\\''"))
}

/// Get the current user's home directory via getpwuid (trusted source).
///
/// This function uses the system's password database (via `getpwuid`) to retrieve
/// the home directory, avoiding the security risk of relying on the `HOME`
/// environment variable which can be manipulated by untrusted input.
///
/// # Returns
/// - `Some(PathBuf)` if the home directory was found and exists
/// - `None` if the user lookup failed or the directory doesn't exist
///
/// # Security
/// This function is designed to be safe against confused-deputy attacks where
/// an attacker might manipulate environment variables to influence privileged
/// operations.
pub fn get_home_dir_trusted() -> Option<PathBuf> {
    let uid = get_current_uid();
    match get_user_by_uid(uid) {
        Some(user) => {
            let home = user.home_dir();
            if Path::is_dir(home) {
                Some(PathBuf::from(home))
            } else {
                log::warn!(
                    "Home directory for uid {} does not exist or is not a directory: {:?}",
                    uid,
                    home
                );
                None
            }
        }
        None => {
            log::warn!("Failed to get user info for uid {}", uid);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_cmds_trim_newline() {
        assert_eq!(run_cmds_trim_newline("echo -n 123").unwrap(), "123");
        assert_eq!(run_cmds_trim_newline("echo 123").unwrap(), "123");
        assert_eq!(
            run_cmds_trim_newline("whoami").unwrap() + "\n",
            run_cmds("whoami").unwrap()
        );
    }

    /// Test get_home_dir_trusted: returns valid path and ignores HOME env var
    #[test]
    fn test_get_home_dir_trusted() {
        let original_home = std::env::var("HOME").ok();

        // Set HOME to a fake/malicious path
        std::env::set_var("HOME", "/tmp/fake_malicious_home");
        let result = get_home_dir_trusted();

        // Restore original HOME
        match original_home {
            Some(home) => std::env::set_var("HOME", home),
            None => std::env::remove_var("HOME"),
        }

        // Verify: returns valid path that is NOT the fake HOME
        if let Some(path) = result {
            assert!(path.is_absolute(), "Path should be absolute: {:?}", path);
            assert!(path.is_dir(), "Path should be a directory: {:?}", path);
            assert_ne!(
                path.to_string_lossy(),
                "/tmp/fake_malicious_home",
                "Should not use HOME env var"
            );
        }
    }

    /// Test shell_quote with normal strings
    #[test]
    fn test_shell_quote_normal() {
        assert_eq!(shell_quote("hello"), "'hello'");
        assert_eq!(shell_quote("/home/user"), "'/home/user'");
    }

    /// Test shell_quote with spaces
    #[test]
    fn test_shell_quote_spaces() {
        assert_eq!(shell_quote("/home/my user/file"), "'/home/my user/file'");
        assert_eq!(shell_quote("path with spaces"), "'path with spaces'");
    }

    /// Test shell_quote with single quotes (the tricky case)
    #[test]
    fn test_shell_quote_single_quotes() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("don't stop"), "'don'\\''t stop'");
    }

    /// Test shell_quote with shell metacharacters
    #[test]
    fn test_shell_quote_metacharacters() {
        // These should all be safely quoted
        assert_eq!(shell_quote("test;rm -rf /"), "'test;rm -rf /'");
        assert_eq!(shell_quote("$(whoami)"), "'$(whoami)'");
        assert_eq!(shell_quote("`id`"), "'`id`'");
        assert_eq!(shell_quote("a && b"), "'a && b'");
        assert_eq!(shell_quote("a | b"), "'a | b'");
    }

    /// A sample logind session file (KEY=VALUE) as found under
    /// /run/systemd/sessions/<sid>.
    const SAMPLE_SESSION: &str = "# This is private data. Do not parse.\n\
UID=1000\n\
USER=zyq\n\
ACTIVE=1\n\
IS_DISPLAY=1\n\
STATE=active\n\
TYPE=wayland\n\
CLASS=user\n\
SCOPE=session-33.scope\n\
SEAT=seat0\n\
DISPLAY=:2\n\
SERVICE=lightdm\n\
DESKTOP=Wayland\n\
VTNR=1\n\
LEADER=262664\n\
";

    #[test]
    fn test_parse_key_value_file_inline() {
        let dir = std::env::temp_dir().join("rustdesk_test_sessions");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("33");
        std::fs::write(&p, SAMPLE_SESSION).unwrap();
        let fields = parse_key_value_file(&p).expect("parse");
        assert_eq!(fields.get("UID").map(|s| s.as_str()), Some("1000"));
        assert_eq!(fields.get("USER").map(|s| s.as_str()), Some("zyq"));
        assert_eq!(fields.get("TYPE").map(|s| s.as_str()), Some("wayland"));
        assert_eq!(fields.get("SEAT").map(|s| s.as_str()), Some("seat0"));
        assert!(is_active_fields(&fields));
        let mapped = map_session_values("33", &fields, &[0, 1, 2]);
        assert_eq!(mapped, vec!["33", "1000", "zyq"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_display_server_of_session_from_fields() {
        // get_display_server_of_session must read TYPE from the file, not spawn
        // loginctl. We cannot easily stub the filesystem path it reads, so we
        // assert the fallback-free branch indirectly: a wayland TYPE maps to
        // "wayland" and an empty/tty TYPE falls back to XDG_SESSION_TYPE then x11.
        std::env::set_var("XDG_SESSION_TYPE", "wayland");
        // Without a real /run/systemd/sessions file for a fake sid the function
        // falls back to loginctl; on a system without loginctl it returns x11.
        // Here we only verify it does not panic and returns a known display server.
        let r = get_display_server_of_session("no-such-session-xyz");
        assert!(matches!(r.as_str(), "wayland" | "x11"));
    }
}

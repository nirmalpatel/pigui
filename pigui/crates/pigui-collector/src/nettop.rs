use std::collections::HashMap;
use std::process::Command;

use pigui_core::Result;
use pigui_core::error::Error;

use crate::{CollectorSnapshot, ProcessSample, SocketSample};

pub fn default_interface() -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines().find_map(|line| {
        line.trim()
            .strip_prefix("interface:")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

pub fn run_nettop(interface_filter: Option<&str>) -> Result<CollectorSnapshot> {
    let output = Command::new("nettop")
        .args(["-L", "1", "-x", "-n"])
        .output()
        .map_err(|error| Error::io("nettop", error))?;

    if !output.status.success() {
        return Err(Error::Parse(format!(
            "nettop exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let mut snapshot = parse_nettop(&String::from_utf8_lossy(&output.stdout), interface_filter);
    enrich_process_metadata(&mut snapshot);
    Ok(snapshot)
}

fn enrich_process_metadata(snapshot: &mut CollectorSnapshot) {
    let Ok(output) = Command::new("ps")
        .args(["-axo", "pid=,user=,comm="])
        .output()
    else {
        return;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut metadata: HashMap<u32, (String, String)> = HashMap::new();

    for line in text.lines() {
        let line = line.trim_start();
        let Some(pid_end) = line.find(char::is_whitespace) else {
            continue;
        };
        let Ok(pid) = line[..pid_end].parse::<u32>() else {
            continue;
        };
        let rest = line[pid_end..].trim_start();
        let user_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let user = rest[..user_end].to_string();
        let command = rest[user_end..].trim_start().to_string();
        if command.is_empty() {
            continue;
        }
        metadata.insert(pid, (user, command));
    }

    for process in &mut snapshot.processes {
        if let Some((user, command)) = metadata.get(&process.pid) {
            if let Some(name) = command.rsplit('/').next().filter(|name| !name.is_empty()) {
                process.name = name.to_string();
            }
            process.path = Some(command.clone());
            process.user = Some(user.clone());
        }
    }
}

/// Parse `nettop -L 1 -x -n` CSV output.
///
/// nettop groups connection rows under a process summary row. The summary
/// subject is `name.pid`; connection rows start with `tcp4`, `tcp6`, `udp4`,
/// or `udp6`.
pub fn parse_nettop(output: &str, interface_filter: Option<&str>) -> CollectorSnapshot {
    let mut snapshot = CollectorSnapshot::default();
    let mut current: Option<(u32, String)> = None;

    for line in output.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let fields = split_csv(line);
        if fields.len() < 6 || fields[0].eq_ignore_ascii_case("time") {
            continue;
        }

        let subject = fields[1].trim();
        if subject.is_empty() {
            continue;
        }
        let interface = empty_to_none(fields[2].trim());
        let state = empty_to_none(fields[3].trim());
        let bytes_in = parse_u64(fields[4].trim());
        let bytes_out = parse_u64(fields[5].trim());

        if is_connection(subject) {
            let Some((pid, process_name)) = &current else {
                continue;
            };
            if let Some(socket) = parse_connection(
                subject,
                interface.clone(),
                state,
                bytes_in,
                bytes_out,
                *pid,
                process_name.clone(),
            ) && interface_filter
                .is_none_or(|filter| socket.interface.as_deref() == Some(filter))
            {
                snapshot.sockets.push(socket);
            }
        } else if interface.is_none()
            && state.is_none()
            && let Some((name, pid)) = parse_process_subject(subject)
        {
            snapshot.processes.push(ProcessSample {
                pid,
                name: name.clone(),
                path: None,
                user: None,
                bytes_in,
                bytes_out,
                connection_count: 0,
            });
            current = Some((pid, name));
        }
    }

    let mut counts: HashMap<u32, u64> = HashMap::new();
    for socket in &snapshot.sockets {
        *counts.entry(socket.pid).or_default() += 1;
    }
    snapshot
        .processes
        .retain(|process| counts.get(&process.pid).copied().unwrap_or(0) > 0);
    for process in &mut snapshot.processes {
        process.connection_count = counts.get(&process.pid).copied().unwrap_or(0);
    }

    snapshot
}

fn is_connection(subject: &str) -> bool {
    (subject.starts_with("tcp") || subject.starts_with("udp")) && subject.contains("<->")
}

fn parse_process_subject(subject: &str) -> Option<(String, u32)> {
    let (name, pid) = subject.rsplit_once('.')?;
    if name.is_empty() {
        return None;
    }
    let pid = pid.parse().ok()?;
    Some((name.to_string(), pid))
}

fn parse_connection(
    subject: &str,
    interface: Option<String>,
    state: Option<String>,
    bytes_in: u64,
    bytes_out: u64,
    pid: u32,
    process_name: String,
) -> Option<SocketSample> {
    if state
        .as_deref()
        .is_some_and(|state| state.eq_ignore_ascii_case("listen"))
    {
        return None;
    }

    let (proto_token, rest) = subject.split_once(char::is_whitespace)?;
    let rest = rest.trim();
    let ipv6 = proto_token.ends_with('6');
    let (local, remote) = rest.split_once("<->")?;
    let (client_ip, client_port) = parse_endpoint(local, ipv6)?;
    let (server_ip, server_port) = parse_endpoint(remote, ipv6)?;

    let proto = if proto_token.starts_with("tcp") {
        "tcp"
    } else if proto_token.starts_with("udp") {
        "udp"
    } else {
        return None;
    };

    Some(SocketSample {
        proto: proto.to_string(),
        client_ip,
        client_port,
        server_ip,
        server_port,
        state,
        interface,
        bytes_ab: bytes_in,
        bytes_ba: bytes_out,
        pid,
        process_name,
    })
}

fn parse_endpoint(value: &str, ipv6: bool) -> Option<(String, u16)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let (host, port) = if ipv6 {
        value.rsplit_once('.')?
    } else {
        value.rsplit_once(':')?
    };

    let host = host.split('%').next().unwrap_or(host);
    if host.is_empty() || host == "*" {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }

    Some((host.to_string(), port))
}

fn parse_u64(value: &str) -> u64 {
    value.parse().unwrap_or(0)
}

fn empty_to_none(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();

    while let Some(character) = chars.next() {
        match character {
            '"' => {
                if quoted && chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    quoted = !quoted;
                }
            }
            ',' if !quoted => fields.push(std::mem::take(&mut current)),
            _ => current.push(character),
        }
    }
    fields.push(current);
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"time,,interface,state,bytes_in,bytes_out,rx_dupe,rx_ooo,re-tx,rtt_avg,rcvsize,tx_win,tc_class,tc_mgt,cc_algo,P,C,R,W,arch,
19:59:28.682552,launchd.1,,,0,0,0,0,0,,,,,,,,,,,,
19:59:28.680979,tcp4 *:445<->*:*,,Listen,,,,,,,,,,-,cubic,-,-,-,-,so,
19:59:28.682570,apsd.348,,,5525,20461,0,0,0,,,,,,,,,,,,
19:59:28.680941,tcp4 192.168.29.54:60293<->17.242.13.5:5223,en0,Established,5525,20461,0,0,0,33.94 ms,131072,31872,RD,-,cubic,-,-,-,-,ch,
19:59:28.682585,kdc.359,,,0,0,0,0,0,,,,,,,,,,,,
19:59:28.681014,tcp4 *:88<->*:*,,Listen,,,,,,,,,,-,cubic,-,-,-,-,so,
19:59:28.682648,mDNSResponder.392,,,256687395,102203133,7984,1112,0,,,,,,,,,,,,
19:59:28.680901,tcp6 2405:201:201f:6915:8951:773:b287:a615.57809<->2606:4700:4700::1001.443,en0,Established,1072929,513957,7984,1112,0,16.84 ms,131072,1630208,BE,-,cubic,-,-,-,-,ch,
19:59:28.679992,udp6 *.5353<->*.*,en0,,127160904,49050154,,,,,786896,,CTL,,,,,,,so,
"#;

    #[test]
    fn parses_processes_and_connections() {
        let snapshot = parse_nettop(SAMPLE, Some("en0"));
        assert_eq!(snapshot.processes.len(), 2);
        assert_eq!(snapshot.sockets.len(), 2);

        let apsd = snapshot
            .processes
            .iter()
            .find(|process| process.pid == 348)
            .unwrap();
        assert_eq!(apsd.name, "apsd");
        assert_eq!(apsd.connection_count, 1);

        let tcp = snapshot
            .sockets
            .iter()
            .find(|socket| socket.proto == "tcp")
            .unwrap();
        assert_eq!(tcp.client_ip, "192.168.29.54");
        assert_eq!(tcp.client_port, 60293);
        assert_eq!(tcp.server_ip, "17.242.13.5");
        assert_eq!(tcp.server_port, 5223);
        assert_eq!(tcp.bytes_ab, 5525);
        assert_eq!(tcp.bytes_ba, 20461);
        assert_eq!(tcp.pid, 348);
    }

    #[test]
    fn parses_ipv6_with_zone() {
        let snapshot = parse_nettop(SAMPLE, Some("en0"));
        let tcp6 = snapshot
            .sockets
            .iter()
            .find(|socket| socket.proto == "tcp" && socket.client_ip.contains(':'))
            .unwrap();
        assert_eq!(tcp6.client_ip, "2405:201:201f:6915:8951:773:b287:a615");
        assert_eq!(tcp6.client_port, 57809);
        assert_eq!(tcp6.server_port, 443);
    }

    #[test]
    fn filters_other_interfaces() {
        let snapshot = parse_nettop(SAMPLE, Some("lo0"));
        assert!(snapshot.sockets.is_empty());
        assert!(snapshot.processes.is_empty());
    }

    #[test]
    fn ignores_listen_and_wildcard_rows() {
        let snapshot = parse_nettop(SAMPLE, None);
        assert!(
            snapshot
                .sockets
                .iter()
                .all(|socket| socket.server_port != 0 && socket.state.as_deref() != Some("Listen"))
        );
    }
}

use crate::model::TelemetryEvent;
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub trait TelemetrySink: Send + Sync {
    fn emit(&self, event: TelemetryEvent);
}

#[derive(Debug)]
pub struct TelemetryClient {
    enabled: bool,
    socket: Option<UdpSocket>,
    endpoint: String,
    dropped: AtomicU64,
}

impl TelemetryClient {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            socket: None,
            endpoint: String::new(),
            dropped: AtomicU64::new(0),
        }
    }

    pub fn from_environment() -> Self {
        if std::env::var("ARC_PILOT_TELEMETRY").ok().as_deref() != Some("local") {
            return Self::disabled();
        }
        let endpoint = std::env::var("ARC_TELEMETRY_ENDPOINT")
            .unwrap_or_else(|_| "127.0.0.1:39741".to_string());
        if !is_loopback_endpoint(&endpoint) {
            return Self::disabled();
        }
        let socket = UdpSocket::bind("127.0.0.1:0").ok();
        if let Some(ref s) = socket {
            let _ = s.set_nonblocking(true);
        }
        Self {
            enabled: socket.is_some(),
            socket,
            endpoint,
            dropped: AtomicU64::new(0),
        }
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

impl TelemetrySink for TelemetryClient {
    fn emit(&self, mut event: TelemetryEvent) {
        if !self.enabled {
            return;
        }
        event.telemetry_dropped_before_event = self.dropped_count();
        let Ok(bytes) = serde_json::to_vec(&event) else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if bytes.len() > 60_000 {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Some(socket) = &self.socket else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if socket.send_to(&bytes, &self.endpoint).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn default_spool_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("ARC_TELEMETRY_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(dir) = dirs_fallback() {
        return dir.join("VexaArc").join("pilot").join("events");
    }
    PathBuf::from(".arc").join("telemetry")
}

fn dirs_fallback() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share"))
            })
    }
}

pub fn run_collector(dir: &Path, endpoint: &str) -> std::io::Result<()> {
    if !is_loopback_endpoint(endpoint) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "telemetry collector must bind to a loopback IP address",
        ));
    }
    fs::create_dir_all(dir)?;
    let socket = UdpSocket::bind(endpoint)?;
    socket.set_read_timeout(Some(std::time::Duration::from_millis(500)))?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match socket.recv(&mut buf) {
            Ok(size) => {
                if serde_json::from_slice::<Value>(&buf[..size]).is_err() {
                    continue;
                }
                append_event(dir, &buf[..size])?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                if std::env::var("ARC_TELEMETRY_ONCE").ok().as_deref() == Some("1") {
                    return Ok(());
                }
            }
            Err(e) => return Err(e),
        }
    }
}

fn is_loopback_endpoint(endpoint: &str) -> bool {
    endpoint
        .parse::<SocketAddr>()
        .map(|address| match address.ip() {
            IpAddr::V4(ip) => ip.is_loopback(),
            IpAddr::V6(ip) => ip.is_loopback(),
        })
        .unwrap_or(false)
}

fn append_event(dir: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let path = dir.join("events.ndjson");
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.flush()
}

pub fn export_aggregate(dir: &Path, out: &Path) -> std::io::Result<()> {
    let path = dir.join("events.ndjson");
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::write(out, b"{}")?;
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let mut counts = serde_json::Map::new();
    let mut total = 0u64;
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            total += 1;
            for key in ["action_class", "decision", "rule_id", "host"] {
                if let Some(value) = v.get(key).and_then(Value::as_str) {
                    let entry = counts
                        .entry(key.to_string())
                        .or_insert_with(|| serde_json::json!({}));
                    if let Some(map) = entry.as_object_mut() {
                        let current = map.get(value).and_then(Value::as_u64).unwrap_or(0);
                        map.insert(value.to_string(), Value::from(current + 1));
                    }
                }
            }
        }
    }
    let output = serde_json::json!({ "events": total, "counts": counts });
    fs::write(out, serde_json::to_vec_pretty(&output).unwrap_or_default())
}

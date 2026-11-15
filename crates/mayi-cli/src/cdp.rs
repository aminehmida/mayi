//! Just enough of the Chrome DevTools Protocol to type into a page: list the
//! tabs over HTTP, then send commands to one over a WebSocket.
//!
//! Only a browser on this machine is accepted. The protocol has no
//! encryption, so a value typed into a browser elsewhere would cross the
//! network in the clear.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};
use tungstenite::{Message, WebSocket};

const TIMEOUT: Duration = Duration::from_secs(10);

/// A browser's debugging port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "http://{}:{}", self.host, self.port)
    }
}

/// An open tab, as the browser lists it.
#[derive(Clone, Debug)]
pub struct Tab {
    pub id: String,
    pub url: String,
    pub title: String,
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

/// Reads a profile's `DevToolsActivePort`, which Chrome writes when started
/// with a debugging port (port 0 included): the port on the first line.
fn active_port(path: &Path) -> Option<Endpoint> {
    let file = if path.is_dir() { path.join("DevToolsActivePort") } else { path.to_path_buf() };
    let text = std::fs::read_to_string(file).ok()?;
    let port = text.lines().next()?.trim().parse().ok()?;
    Some(Endpoint { host: "127.0.0.1".into(), port })
}

/// Understands `http://127.0.0.1:9222`, `127.0.0.1:9222`, `9222`, or the
/// path of a browser profile folder started with a debugging port.
pub fn parse_endpoint(text: &str) -> Result<Endpoint, String> {
    let text = text.trim();
    let path = Path::new(text);
    if text.starts_with(['/', '.', '~']) || path.is_dir() {
        return active_port(path).ok_or(format!("{text} holds no running browser profile (no DevToolsActivePort)"));
    }
    let rest = text.split_once("://").map_or(text, |(_, rest)| rest);
    let rest = rest.split('/').next().unwrap_or("");
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (host, port),
        None if rest.chars().all(|c| c.is_ascii_digit()) => ("127.0.0.1", rest),
        None => (rest, "9222"),
    };
    let port = port.parse().map_err(|_| format!("{text:?} has no valid port"))?;
    if !is_loopback(host) {
        return Err(format!(
            "{host} is not this machine. Mayi types into a browser on the same machine only, \
             because the debugging protocol is not encrypted. Run mayi fill where the browser runs."
        ));
    }
    let host = if host == "[::1]" || host == "::1" { "[::1]".into() } else { host.to_string() };
    Ok(Endpoint { host, port })
}

/// Where to look for a browser when none is named: the default port, the
/// profile `mayi browser` uses, and the one Chrome DevTools MCP starts.
pub fn default_endpoints() -> Vec<Endpoint> {
    let mut found = vec![Endpoint { host: "127.0.0.1".into(), port: 9222 }];
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let mut profiles = vec![browser_profile()];
    if let Ok(entries) = std::fs::read_dir(home.join(".cache/chrome-devtools-mcp")) {
        profiles.extend(entries.flatten().map(|e| e.path()));
    }
    for profile in profiles {
        if let Some(endpoint) = active_port(&profile) {
            if !found.contains(&endpoint) {
                found.push(endpoint);
            }
        }
    }
    found
}

/// The profile folder of the browser `mayi browser` starts.
pub fn browser_profile() -> PathBuf {
    let data = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share")
    });
    data.join("mayi/browser")
}

fn connect(endpoint: &Endpoint) -> io::Result<TcpStream> {
    let host = endpoint.host.trim_start_matches('[').trim_end_matches(']');
    let addr = (host, endpoint.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "address did not resolve"))?;
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// A plain HTTP GET, enough for the browser's `/json` pages.
fn get(endpoint: &Endpoint, path: &str) -> io::Result<Value> {
    let mut stream = connect(endpoint)?;
    write!(stream, "GET {path} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n", endpoint.host, endpoint.port)?;
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader.read_line(&mut status)?;
    if !status.split_whitespace().nth(1).is_some_and(|code| code == "200") {
        return Err(io::Error::other(format!("the browser answered {}", status.trim())));
    }
    let mut length = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse::<usize>().ok();
            }
        }
    }
    let mut body = Vec::new();
    match length {
        Some(n) => {
            body.resize(n, 0);
            reader.read_exact(&mut body)?;
        }
        None => {
            reader.read_to_end(&mut body)?;
        }
    }
    serde_json::from_slice(&body).map_err(io::Error::other)
}

/// The web pages open in the browser, most recently used first.
pub fn tabs(endpoint: &Endpoint) -> io::Result<Vec<Tab>> {
    let list = get(endpoint, "/json/list")?;
    let tabs = list.as_array().cloned().unwrap_or_default();
    Ok(tabs
        .iter()
        .filter(|t| t["type"] == "page")
        .filter_map(|t| {
            Some(Tab {
                id: t["id"].as_str()?.to_string(),
                url: t["url"].as_str().unwrap_or_default().to_string(),
                title: t["title"].as_str().unwrap_or_default().to_string(),
            })
        })
        .filter(|t| t.url.starts_with("https://") || t.url.starts_with("http://"))
        .collect())
}

/// Whether a browser answers on this port.
pub fn version(endpoint: &Endpoint) -> io::Result<String> {
    let info = get(endpoint, "/json/version")?;
    Ok(info["Browser"].as_str().unwrap_or("a browser").to_string())
}

/// A conversation with one tab.
pub struct Session {
    ws: WebSocket<TcpStream>,
    next_id: u64,
    /// Events that arrived while waiting for answers.
    events: Vec<Value>,
}

impl Session {
    pub fn open(endpoint: &Endpoint, tab: &Tab) -> io::Result<Session> {
        let stream = connect(endpoint)?;
        let url = format!("ws://{}:{}/devtools/page/{}", endpoint.host, endpoint.port, tab.id);
        // No Origin header is sent, which is how the browser tells a
        // debugging client from a web page trying to reach the port.
        let (ws, _) = tungstenite::client::client(url.as_str(), stream).map_err(io::Error::other)?;
        Ok(Session { ws, next_id: 0, events: Vec::new() })
    }

    /// Sends one command and waits for its answer, skipping events.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.next_id += 1;
        let id = self.next_id;
        let message = json!({ "id": id, "method": method, "params": params }).to_string();
        self.ws.send(Message::Text(message.into())).map_err(|e| format!("browser connection lost: {e}"))?;
        loop {
            let message = self.ws.read().map_err(|e| format!("browser connection lost: {e}"))?;
            let Ok(text) = message.to_text() else { continue };
            let Ok(reply) = serde_json::from_str::<Value>(text) else { continue };
            if reply.get("method").is_some() {
                self.events.push(reply);
                continue;
            }
            if reply["id"].as_u64() != Some(id) {
                continue;
            }
            if let Some(error) = reply.get("error") {
                return Err(error["message"].as_str().unwrap_or("the browser refused").to_string());
            }
            return Ok(reply["result"].clone());
        }
    }

    /// The events received since the last call, oldest first.
    pub fn take_events(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        let ep = |host: &str, port| Endpoint { host: host.into(), port };
        assert_eq!(parse_endpoint("http://127.0.0.1:9333").unwrap(), ep("127.0.0.1", 9333));
        assert_eq!(parse_endpoint("localhost:9222/json").unwrap(), ep("localhost", 9222));
        assert_eq!(parse_endpoint("9229").unwrap(), ep("127.0.0.1", 9229));
        assert_eq!(parse_endpoint("http://[::1]:9222").unwrap(), ep("[::1]", 9222));
        for remote in ["http://10.0.0.5:9222", "build-vm:9222", "http://example.com:9222"] {
            assert!(parse_endpoint(remote).unwrap_err().contains("not this machine"), "{remote}");
        }
        assert!(parse_endpoint("/nonexistent/profile").is_err());

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("DevToolsActivePort"), "51234\n/devtools/browser/abc\n").unwrap();
        assert_eq!(parse_endpoint(dir.path().to_str().unwrap()).unwrap(), ep("127.0.0.1", 51234));
    }
}

//! `mayi browser`: starts Chrome or Chromium with a debugging port on this
//! machine and a profile of its own, for the agent's browser tool and for
//! `mayi fill` to share. Its own profile keeps the agent out of the user's
//! everyday sessions, and Chrome refuses a debugging port on the default
//! profile anyway.

use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::cdp::{self, Endpoint};
use crate::{Failure, EXIT_UNAVAILABLE};

fn find_chrome() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("MAYI_CHROME") {
        return Some(path.into());
    }
    let apps = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ];
    if let Some(app) = apps.iter().map(PathBuf::from).find(|p| p.exists()) {
        return Some(app);
    }
    let names = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave-browser", "microsoft-edge"];
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|candidate| candidate.is_file())
}

fn instructions(endpoint: &Endpoint) {
    println!("Point your agent's browser tool at it:");
    println!("  Playwright MCP:       npx @playwright/mcp@latest --cdp-endpoint {endpoint}");
    println!("  Chrome DevTools MCP:  npx chrome-devtools-mcp@latest --browser-url {endpoint}");
    println!("mayi fill finds it there without options.");
}

pub fn start(port: u16, headless: bool) -> Result<u8, Failure> {
    let endpoint = Endpoint { host: "127.0.0.1".into(), port };
    if let Ok(name) = cdp::version(&endpoint) {
        println!("{name} is already listening on {endpoint}.");
        instructions(&endpoint);
        return Ok(0);
    }
    let chrome = find_chrome().ok_or((
        EXIT_UNAVAILABLE,
        "found no Chrome or Chromium. Install one, or set MAYI_CHROME to its executable.".to_string(),
    ))?;
    let profile = cdp::browser_profile();
    std::fs::create_dir_all(&profile).map_err(|e| (EXIT_UNAVAILABLE, format!("{}: {e}", profile.display())))?;

    let mut command = Command::new(&chrome);
    command
        .arg(format!("--remote-debugging-port={port}"))
        .arg("--remote-debugging-address=127.0.0.1")
        .arg(format!("--user-data-dir={}", profile.display()))
        .args(["--no-first-run", "--no-default-browser-check"]);
    if headless {
        command.arg("--headless=new");
    }
    // Chrome will not start as root with its sandbox, which is how agents
    // often run in containers. Only then is the sandbox turned off.
    // SAFETY: plain syscall with no arguments.
    if cfg!(target_os = "linux") && unsafe { libc::geteuid() } == 0 {
        command.arg("--no-sandbox");
    }
    command.arg("about:blank");
    // Its own process group, so it outlives this command and the terminal.
    command.process_group(0).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    command.spawn().map_err(|e| (EXIT_UNAVAILABLE, format!("cannot start {}: {e}", chrome.display())))?;

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(name) = cdp::version(&endpoint) {
            println!("Started {name} on {endpoint}, with its own profile in {}.", profile.display());
            instructions(&endpoint);
            return Ok(0);
        }
        if Instant::now() >= deadline {
            return Err((
                EXIT_UNAVAILABLE,
                format!(
                    "{} did not open a debugging port on {endpoint}. If that profile is already open \
                     in a browser started without one, quit it and try again.",
                    chrome.display()
                ),
            ));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

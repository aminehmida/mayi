//! `mayi mcp`: the command line's operations as a Model Context Protocol
//! server on stdin/stdout, for agents that have no shell.
//!
//! There is deliberately no tool that returns a secret's value. A command's
//! output comes back with the values masked, exactly as `mayi run` prints it.

use std::io::{self, BufRead, Write};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
/// More output than this is cut, so one command cannot flood the context.
const MAX_OUTPUT: usize = 60_000;

const INSTRUCTIONS: &str = "Mayi lets you use the user's secrets without seeing them. \
Call list_secrets to learn which names exist, then run_with_secrets to run a command with \
the ones it needs as environment variables. The user may be asked to approve, and sees the \
exact command and your reason. Secret values in the output are replaced with [masked]. \
To sign in to a website, open its sign-in page with your browser tool and call fill_login: \
Mayi types the login into the page itself. Never type a password or code yourself, and never \
try to print, encode or send a secret's value anywhere other than the tool it is for.";

fn tools() -> Value {
    json!([
        {
            "name": "list_secrets",
            "description": "List the secrets available through Mayi: name, level (1 log, 2 notify, 3 approve, 4 biometric), field names, and for a login the websites it is for. Values are never returned.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "name": "run_with_secrets",
            "description": "Run a command with secrets injected as environment variables. The user sees the exact command and your reason, and may have to approve. Returns the exit code and the output with secret values masked.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "array", "items": { "type": "string" }, "minItems": 1,
                        "description": "The program and its arguments, one per element. No shell is involved unless you run one, e.g. [\"sh\", \"-c\", \"...\"]."
                    },
                    "secrets": {
                        "type": "array", "items": { "type": "string" }, "minItems": 1,
                        "description": "Each as ENV=NAME, ENV=NAME/FIELD, or NAME to use the secret's name as the variable."
                    },
                    "reason": {
                        "type": "string",
                        "description": "Why the secrets are needed, in a sentence the user can judge. It is shown to them and logged."
                    },
                    "timeout_seconds": {
                        "type": "integer", "minimum": 1,
                        "description": "How long to wait for the user's decision. Default 120."
                    }
                },
                "required": ["command", "secrets", "reason"],
                "additionalProperties": false
            }
        },
        {
            "name": "fill_login",
            "description": "Sign in to a website with one of the user's logins. First open the site's sign-in page with your browser tool. Mayi reads the page's address from the browser, checks it is one of the login's websites, asks the user if needed, then types the username, password or two-factor code the page asks for and presses Enter. Nothing typed is returned. If the next page asks for more, call it again. The browser must have a debugging port Mayi can reach (see `mayi browser`).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "login": { "type": "string", "description": "The login's name, as list_secrets shows it." },
                    "reason": {
                        "type": "string",
                        "description": "Why you are signing in, in a sentence the user can judge. It is shown to them and logged."
                    },
                    "tab": {
                        "type": "string",
                        "description": "Text in the address or title of the tab to fill, if several tabs are open on the site."
                    },
                    "submit_selector": {
                        "type": "string",
                        "description": "CSS selector of the button to click to submit, for a form that Enter does not submit. By default Mayi presses Enter."
                    },
                    "timeout_seconds": {
                        "type": "integer", "minimum": 1,
                        "description": "How long to wait for the user's decision. Default 120."
                    }
                },
                "required": ["login", "reason"],
                "additionalProperties": false
            }
        }
    ])
}

fn text_result(text: String, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

fn clip(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= MAX_OUTPUT {
        return text.into_owned();
    }
    let mut end = MAX_OUTPUT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[output cut after {MAX_OUTPUT} bytes]", &text[..end])
}

/// Runs this same program as `mayi <args>`, so the MCP tools behave exactly
/// like the command line, masking included.
fn run_self(args: &[String]) -> Result<(Option<i32>, String, String), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let output = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    Ok((output.status.code(), clip(&output.stdout), clip(&output.stderr)))
}

fn strings(value: Option<&Value>, what: &str) -> Result<Vec<String>, String> {
    let list = value.and_then(Value::as_array).filter(|a| !a.is_empty());
    let list = list.ok_or_else(|| format!("{what} must be a non-empty array of strings"))?;
    list.iter()
        .map(|v| v.as_str().map(String::from).ok_or_else(|| format!("{what} must contain only strings")))
        .collect()
}

/// The `mayi run` arguments for a run_with_secrets call.
fn run_args(arguments: &Value, client: &str) -> Result<Vec<String>, String> {
    let command = strings(arguments.get("command"), "command")?;
    let secrets = strings(arguments.get("secrets"), "secrets")?;
    let reason = arguments.get("reason").and_then(Value::as_str).map(str::trim).filter(|r| !r.is_empty());
    let reason = reason.ok_or("reason must be a non-empty string")?;
    let timeout = arguments.get("timeout_seconds").and_then(Value::as_u64).unwrap_or(120);
    let mut args = vec!["run".to_string()];
    for secret in secrets {
        // As one argument each, so a value starting with `-` cannot become a flag.
        args.push(format!("--secret={secret}"));
    }
    args.push(format!("--reason={reason}"));
    args.push(format!("--agent={client}"));
    args.push(format!("--session=mcp:{}", std::os::unix::process::parent_id()));
    args.push(format!("--timeout={timeout}"));
    args.push("--".into());
    args.extend(command);
    Ok(args)
}

/// The `mayi fill` arguments for a fill_login call.
fn fill_args(arguments: &Value, client: &str) -> Result<Vec<String>, String> {
    let text = |name: &str| arguments.get(name).and_then(Value::as_str).map(str::trim).filter(|t| !t.is_empty());
    let login = text("login").ok_or("login must be a non-empty string")?;
    let reason = text("reason").ok_or("reason must be a non-empty string")?;
    let timeout = arguments.get("timeout_seconds").and_then(Value::as_u64).unwrap_or(120);
    let mut args = vec![
        "fill".to_string(),
        format!("--reason={reason}"),
        format!("--agent={client}"),
        format!("--session=mcp:{}", std::os::unix::process::parent_id()),
        format!("--timeout={timeout}"),
    ];
    if let Some(tab) = text("tab") {
        args.push(format!("--tab={tab}"));
    }
    if let Some(css) = text("submit_selector") {
        args.push(format!("--submit-selector={css}"));
    }
    // After `--`, so a name starting with `-` cannot become a flag.
    args.push("--".into());
    args.push(login.to_string());
    Ok(args)
}

fn call_tool(params: &Value, client: &str) -> Value {
    let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
    let outcome = match params.get("name").and_then(Value::as_str) {
        Some("list_secrets") => run_self(&["list".to_string()]).map(|(code, out, err)| {
            if code == Some(0) { (out, false) } else { (err, true) }
        }),
        Some("run_with_secrets") => run_args(&arguments, client).and_then(|args| run_self(&args)).map(
            |(code, out, err)| {
                let code_text = code.map_or("killed by a signal".to_string(), |c| c.to_string());
                (format!("exit code: {code_text}\n--- stdout ---\n{out}\n--- stderr ---\n{err}"), code != Some(0))
            },
        ),
        Some("fill_login") => fill_args(&arguments, client).and_then(|args| run_self(&args)).map(
            |(code, out, err)| if code == Some(0) { (out, false) } else { (err, true) },
        ),
        other => Err(format!("unknown tool: {}", other.unwrap_or("(none)"))),
    };
    match outcome {
        Ok((text, is_error)) => text_result(text, is_error),
        Err(message) => text_result(message, true),
    }
}

/// Answers one JSON-RPC message. Notifications get no answer.
fn handle(message: &Value, client: &mut String) -> Option<Value> {
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
    let result = match method {
        "initialize" => {
            if let Some(name) = params.pointer("/clientInfo/name").and_then(Value::as_str) {
                *client = name.chars().filter(|c| !c.is_control()).take(64).collect();
            }
            let asked = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
            let version = if PROTOCOL_VERSIONS.contains(&asked) { asked } else { PROTOCOL_VERSIONS[0] };
            Ok(json!({
                "protocolVersion": version,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mayi", "version": env!("CARGO_PKG_VERSION") },
                "instructions": INSTRUCTIONS,
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => Ok(call_tool(&params, client)),
        _ => Err(json!({ "code": -32601, "message": format!("method not found: {method}") })),
    };
    // A message without an id is a notification: nothing to send back.
    let id = id?;
    Some(match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(error) => json!({ "jsonrpc": "2.0", "id": id, "error": error }),
    })
}

pub fn serve() -> io::Result<()> {
    let mut client = "mcp-client".to_string();
    let mut out = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(message) => handle(&message, &mut client),
            Err(_) => Some(json!({
                "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "parse error" }
            })),
        };
        if let Some(reply) = reply {
            writeln!(out, "{reply}")?;
            out.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_and_tool_list() {
        let mut client = String::new();
        let init = handle(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-03-26", "clientInfo": {"name": "claude-desktop\u{7}", "version": "1"}
            }}),
            &mut client,
        )
        .unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(init["result"]["serverInfo"]["name"], "mayi");
        assert_eq!(client, "claude-desktop");
        let unknown = handle(
            &json!({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}}),
            &mut client,
        )
        .unwrap();
        assert_eq!(unknown["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);

        assert!(handle(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}), &mut client).is_none());
        let list = handle(&json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}), &mut client).unwrap();
        let names: Vec<&str> =
            list["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["list_secrets", "run_with_secrets", "fill_login"], "no tool reads a value");
        let missing = handle(&json!({"jsonrpc": "2.0", "id": 4, "method": "resources/list"}), &mut client).unwrap();
        assert_eq!(missing["error"]["code"], -32601);
    }

    #[test]
    fn run_arguments_cannot_smuggle_flags() {
        let args = run_args(
            &json!({"command": ["gh", "pr", "list"], "secrets": ["GH_TOKEN", "--remote"], "reason": " list PRs ", "timeout_seconds": 30}),
            "cursor",
        )
        .unwrap();
        assert_eq!(&args[..3], ["run", "--secret=GH_TOKEN", "--secret=--remote"]);
        assert!(args.contains(&"--reason=list PRs".to_string()));
        assert!(args.contains(&"--agent=cursor".to_string()));
        assert!(args.contains(&"--timeout=30".to_string()));
        assert_eq!(&args[args.len() - 4..], ["--", "gh", "pr", "list"]);

        for bad in [
            json!({"command": [], "secrets": ["A"], "reason": "x"}),
            json!({"command": ["a"], "secrets": [], "reason": "x"}),
            json!({"command": ["a"], "secrets": ["A"], "reason": "  "}),
            json!({"command": ["a", 1], "secrets": ["A"], "reason": "x"}),
            json!({"command": "ls", "secrets": ["A"], "reason": "x"}),
        ] {
            assert!(run_args(&bad, "c").is_err(), "{bad}");
        }
    }

    #[test]
    fn fill_arguments_cannot_smuggle_flags() {
        let args = fill_args(&json!({"login": "--remote", "reason": "check billing", "tab": "login", "submit_selector": "#go"}), "cursor").unwrap();
        assert_eq!(args[0], "fill");
        assert!(args.contains(&"--reason=check billing".to_string()));
        assert!(args.contains(&"--tab=login".to_string()));
        assert!(args.contains(&"--submit-selector=#go".to_string()));
        assert_eq!(&args[args.len() - 2..], ["--", "--remote"]);
        assert!(fill_args(&json!({"login": "github"}), "c").is_err());
        assert!(fill_args(&json!({"login": " ", "reason": "x"}), "c").is_err());
    }

    #[test]
    fn bad_calls_are_tool_errors_not_crashes() {
        let mut client = "c".to_string();
        let reply = handle(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_secret", "arguments": {}}}),
            &mut client,
        )
        .unwrap();
        assert_eq!(reply["result"]["isError"], true);
        let reply = handle(
            &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "run_with_secrets", "arguments": {"command": ["ls"]}}}),
            &mut client,
        )
        .unwrap();
        assert_eq!(reply["result"]["isError"], true);
        assert!(reply["result"]["content"][0]["text"].as_str().unwrap().contains("secrets must be"));
    }

    #[test]
    fn long_output_is_cut_on_a_character_boundary() {
        let long = "é".repeat(MAX_OUTPUT);
        let cut = clip(long.as_bytes());
        assert!(cut.len() < long.len());
        assert!(cut.ends_with("bytes]"));
    }
}

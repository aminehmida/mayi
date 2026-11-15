//! `mayi fill`: types a login into the sign-in page open in the agent's
//! browser. The site is read from the browser, the vault device checks it
//! against the login's websites, and the values go straight from the vault
//! device into the page. Nothing typed is printed.

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use mayi_proto::site::{self, Origin};
use mayi_proto::{write_frame, Binding, ClientMsg, RunRequest, SecretInfo, ServerMsg, FIELD_PASSWORD, FIELD_TOTP, FIELD_USERNAME};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::cdp::{self, Endpoint, Session, Tab};
use crate::{reach, replies, requester_identity, Channel, Failure, Patience, EXIT_DENIED, EXIT_UNAVAILABLE, EXIT_USAGE};

/// The page cannot be filled: no sign-in field, the wrong site, a form Mayi
/// refuses, or a page that changed under it.
pub const EXIT_PAGE: u8 = 65;

const FINDER: &str = include_str!("fill.js");

pub struct FillArgs {
    pub login: String,
    pub reason: String,
    pub agent: Option<String>,
    pub session: Option<String>,
    pub patience: Patience,
    pub remote: bool,
    pub browser: Option<String>,
    pub tab: Option<String>,
    pub submit_selector: Option<String>,
    pub username_selector: Option<String>,
    pub password_selector: Option<String>,
    pub code_selector: Option<String>,
}

fn page(message: impl Into<String>) -> Failure {
    (EXIT_PAGE, message.into())
}

/// The tab to fill: the one named with `--tab`, or else the most recently
/// used tab on one of the login's websites.
fn choose_tab(args: &FillArgs, login: &SecretInfo) -> Result<(Endpoint, Tab), Failure> {
    let endpoints = match &args.browser {
        Some(text) => vec![cdp::parse_endpoint(text).map_err(|e| (EXIT_USAGE, e))?],
        None => cdp::default_endpoints(),
    };
    let mut open = Vec::new();
    let mut tried = Vec::new();
    for endpoint in &endpoints {
        match cdp::tabs(endpoint) {
            Ok(tabs) => open.extend(tabs.into_iter().map(|t| (endpoint.clone(), t))),
            Err(e) => tried.push(format!("{endpoint}: {e}")),
        }
    }
    if open.is_empty() && !tried.is_empty() && tried.len() == endpoints.len() {
        return Err((
            EXIT_UNAVAILABLE,
            format!(
                "no browser with a debugging port found ({}). Start one with `mayi browser` and point \
                 your browser tool at it, or pass --browser with the port your browser tool uses.",
                tried.join("; ")
            ),
        ));
    }
    let wanted: Vec<&(Endpoint, Tab)> = match &args.tab {
        Some(text) => open.iter().filter(|(_, t)| t.url.contains(text.as_str()) || t.title.contains(text.as_str())).collect(),
        None => open
            .iter()
            .filter(|(_, t)| Origin::parse(&t.url).is_ok_and(|o| site::matches_any(&login.sites, &o)))
            .collect(),
    };
    if let Some(found) = wanted.first() {
        return Ok((*found).clone());
    }
    let listing: Vec<&str> = open.iter().map(|(_, t)| t.url.as_str()).collect();
    let listing = if listing.is_empty() { "none".to_string() } else { listing.join(", ") };
    Err(page(match &args.tab {
        Some(text) => format!("no open tab matches {text:?}. Open tabs: {listing}"),
        None => format!(
            "no open tab is on a website of {} ({}). Open its sign-in page first. Open tabs: {listing}",
            login.name,
            login.sites.join(", ")
        ),
    }))
}

/// The origin of the tab's main frame, as the browser reports it.
fn frame(session: &mut Session) -> Result<(String, String, String), Failure> {
    let tree = session.call("Page.getFrameTree", json!({})).map_err(|e| (EXIT_UNAVAILABLE, e))?;
    let frame = &tree["frameTree"]["frame"];
    let id = frame["id"].as_str().unwrap_or_default().to_string();
    let url = frame["url"].as_str().unwrap_or_default().to_string();
    let origin = frame["securityOrigin"].as_str().filter(|o| o.contains("://")).unwrap_or(&url).to_string();
    Ok((id, url, origin))
}

/// Runs an expression in Mayi's isolated world and returns its value.
fn evaluate(session: &mut Session, context: i64, expression: &str) -> Result<Value, String> {
    let result = session.call(
        "Runtime.evaluate",
        json!({ "expression": expression, "contextId": context, "returnByValue": true }),
    )?;
    if let Some(exception) = result.get("exceptionDetails") {
        let text = exception["exception"]["description"].as_str().or(exception["text"].as_str());
        return Err(text.unwrap_or("script error").to_string());
    }
    Ok(result["result"]["value"].clone())
}

fn changed() -> Failure {
    page("the page changed while waiting for approval; nothing was typed. Run mayi fill again on the new page.")
}

/// Focuses a field, types `text` into it, and checks it took. Returns false
/// if the page went on to another one as soon as it was typed, as a form
/// that submits itself on the last digit of a code does.
fn type_into(session: &mut Session, context: i64, name: &str, index: usize, text: &str) -> Result<bool, Failure> {
    let call = format!("mayiFill.focus({}, {index})", json!(name));
    let focus = evaluate(session, context, &call).map_err(|_| changed())?;
    if focus != "ok" {
        return Err(page(format!("could not type the {}: {}", label(name), focus.as_str().unwrap_or("unknown"))));
    }
    session.call("Input.insertText", json!({ "text": text })).map_err(|e| (EXIT_UNAVAILABLE, e))?;
    let check = format!("mayiFill.holds({}, {index}, {})", json!(name), text.chars().count());
    match evaluate(session, context, &check) {
        Ok(Value::Bool(true)) => Ok(true),
        // The script world goes with the page: it navigated.
        Err(_) => Ok(false),
        Ok(_) => Err(page(format!("the {} field did not take what was typed", label(name)))),
    }
}

fn label(field: &str) -> &str {
    match field {
        "code" => "two-factor code",
        other => other,
    }
}

/// Clicks the element `css` names, with a real mouse click at its centre.
fn click(session: &mut Session, context: i64, css: &str) -> Result<(), Failure> {
    let point = evaluate(session, context, &format!("mayiFill.point({})", json!(css))).map_err(|_| changed())?;
    let (Some(x), Some(y)) = (point["x"].as_f64(), point["y"].as_f64()) else {
        return Err(page(format!("{css} does not name a visible element to click")));
    };
    click_at(session, x, y)
}

fn click_at(session: &mut Session, x: f64, y: f64) -> Result<(), Failure> {
    for kind in ["mouseMoved", "mousePressed", "mouseReleased"] {
        session
            .call("Input.dispatchMouseEvent", json!({ "type": kind, "x": x, "y": y, "button": "left", "clickCount": 1 }))
            .map_err(|e| (EXIT_UNAVAILABLE, e))?;
    }
    Ok(())
}

/// What the page did after the form was submitted.
enum Settled {
    /// It went to another address, started loading one, or took the
    /// password out of view.
    MovedOn,
    /// The password is still in a visible field.
    Stayed,
}

/// Waits for the page to react to the submission. A password must not be
/// left in the page: an agent's browser tool may read field values into the
/// model's context (Playwright's snapshots do).
fn settle(session: &mut Session, context: i64, frame_id: &str, url: &str, password_len: Option<usize>) -> Settled {
    let wait = if password_len.is_some() { Duration::from_secs(5) } else { Duration::from_secs(1) };
    let deadline = Instant::now() + wait;
    loop {
        let navigating = session.take_events().iter().any(|event| {
            let method = event["method"].as_str().unwrap_or_default();
            let params = &event["params"];
            let frame = params["frameId"].as_str().or(params["frame"]["id"].as_str());
            frame == Some(frame_id)
                && matches!(
                    method,
                    "Page.frameRequestedNavigation" | "Page.frameStartedLoading" | "Page.frameNavigated" | "Page.navigatedWithinDocument"
                )
        });
        if navigating {
            return Settled::MovedOn;
        }
        match frame(session) {
            Ok((id, now, _)) if id == frame_id && now == url => {}
            _ => return Settled::MovedOn,
        }
        if let Some(len) = password_len {
            // The script world goes with the document, so an error means the page changed.
            match evaluate(session, context, &format!("mayiFill.lingers('password', {len})")) {
                Ok(Value::Bool(true)) => {}
                _ => return Settled::MovedOn,
            }
        }
        if Instant::now() >= deadline {
            return if password_len.is_some() { Settled::Stayed } else { Settled::MovedOn };
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn press_enter(session: &mut Session) -> Result<(), String> {
    for kind in ["keyDown", "keyUp"] {
        let mut event = json!({
            "type": kind, "key": "Enter", "code": "Enter",
            "windowsVirtualKeyCode": 13, "nativeVirtualKeyCode": 13,
        });
        if kind == "keyDown" {
            event["text"] = json!("\r");
        }
        session.call("Input.dispatchKeyEvent", event)?;
    }
    Ok(())
}

pub fn fill(args: FillArgs) -> Result<u8, Failure> {
    // Any device can say what the login is for; the sign-in itself is
    // asked of all of them below.
    let login = {
        let Channel { reader, mut writer } = reach::any(args.remote, args.patience.wait)?;
        write_frame(&mut writer, &ClientMsg::List)
            .map_err(|e| (EXIT_UNAVAILABLE, format!("vault device connection lost: {e}")))?;
        match replies(reader).recv_timeout(Duration::from_secs(10)) {
            Ok(ServerMsg::Secrets { secrets }) => secrets.into_iter().find(|s| s.name == args.login),
            Ok(ServerMsg::Error { message }) => return Err((EXIT_UNAVAILABLE, message)),
            _ => return Err((EXIT_UNAVAILABLE, "no usable reply from the vault device".into())),
        }
    };
    let login = login.ok_or((EXIT_USAGE, format!("no secret named {} (see `mayi list`)", args.login)))?;
    if !login.login {
        return Err((
            EXIT_USAGE,
            format!("{} is not a login. Use `mayi run` to give a secret to a command.", login.name),
        ));
    }

    let (endpoint, tab) = choose_tab(&args, &login)?;
    let mut session = Session::open(&endpoint, &tab).map_err(|e| (EXIT_UNAVAILABLE, format!("{endpoint}: {e}")))?;
    // Navigation events, to tell when a submitted form has moved on.
    session.call("Page.enable", json!({})).map_err(|e| (EXIT_UNAVAILABLE, e))?;
    let (frame_id, url, origin_text) = frame(&mut session)?;
    let origin = Origin::parse(&origin_text).map_err(page)?;
    if !site::matches_any(&login.sites, &origin) {
        return Err(page(format!("{} is for {}, and the tab is on {origin}", login.name, login.sites.join(", "))));
    }

    // Mayi's own script world in the main frame: the page cannot reach it.
    let world = session
        .call("Page.createIsolatedWorld", json!({ "frameId": frame_id, "worldName": "mayi-fill" }))
        .map_err(|e| (EXIT_UNAVAILABLE, e))?;
    let context = world["executionContextId"].as_i64().ok_or((EXIT_UNAVAILABLE, "the browser gave no script context".into()))?;
    evaluate(&mut session, context, FINDER).map_err(|e| (EXIT_UNAVAILABLE, e))?;
    let options = json!({
        "username": args.username_selector, "password": args.password_selector, "code": args.code_selector,
    });
    let found = evaluate(&mut session, context, &format!("mayiFill.find({options})")).map_err(|e| (EXIT_UNAVAILABLE, e))?;
    if found["ok"] != true {
        return Err(page(found["error"].as_str().unwrap_or("could not read the page").to_string()));
    }

    let has = |field: &str| login.fields.iter().any(|f| f == field);
    let code_boxes = found["code"].as_u64().unwrap_or(0) as usize;
    let mut wanted: Vec<&str> = Vec::new();
    if found["username"] == true && has(FIELD_USERNAME) {
        wanted.push(FIELD_USERNAME);
    }
    if found["password"] == true {
        wanted.push(FIELD_PASSWORD);
    }
    if code_boxes > 0 && has(FIELD_TOTP) {
        wanted.push(FIELD_TOTP);
    }
    if wanted.is_empty() {
        return Err(page(if code_boxes > 0 {
            format!("{url} asks for a two-factor code, and {} has no two-factor key", login.name)
        } else if found["username"] == true {
            format!("{url} asks for a username, and {} has none", login.name)
        } else {
            format!(
                "found no sign-in field on {url}. If the page has one, name it with --username-selector, \
                 --password-selector or --code-selector."
            )
        }));
    }

    let (agent, session_id) = requester_identity(args.agent, args.session);
    let request = RunRequest {
        bindings: wanted
            .iter()
            .map(|field| Binding { env: field.to_string(), item: login.name.clone(), field: field.to_string() })
            .collect(),
        argv: vec![],
        cwd: std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default(),
        reason: args.reason,
        agent,
        session: session_id,
        host: crate::hostname(),
        site: Some(origin.to_string()),
    };
    let reach::Answer { reply, replies, mut writer } =
        reach::ask(&request, args.remote, args.patience.wait, args.patience.timeout)?;
    let values: Zeroizing<Vec<(String, Zeroizing<String>)>> = match reply {
        ServerMsg::Released { env, .. } => Zeroizing::new(env.into_iter().map(|(k, v)| (k, Zeroizing::new(v))).collect()),
        ServerMsg::Denied { reason } => return Err((EXIT_DENIED, format!("denied: {reason}"))),
        _ => return Err((EXIT_UNAVAILABLE, "unexpected reply from the vault device".into())),
    };

    let password_len = values.iter().find(|(name, _)| name == FIELD_PASSWORD).map(|(_, v)| v.chars().count());
    // The field typed last, which submitting starts from.
    let last_field = match wanted.last() {
        Some(&FIELD_TOTP) => ("code", code_boxes.saturating_sub(1)),
        Some(&field) => (field, 0),
        None => ("password", 0),
    };
    let typed = type_values(&mut session, context, &frame_id, &origin, &values, code_boxes, &replies);
    drop(values);
    let outcome = typed.and_then(|()| {
        // A code typed digit by digit often submits the form by itself.
        thread::sleep(Duration::from_millis(300));
        match frame(&mut session) {
            Ok((id, now, _)) if id == frame_id && now == url => {}
            _ => return Ok(None),
        }
        let how = match &args.submit_selector {
            Some(css) => {
                click(&mut session, context, css)?;
                format!("clicked {css}")
            }
            None => {
                let (field, index) = last_field;
                let call = format!("mayiFill.submitter({}, {index})", json!(field));
                let submitter = evaluate(&mut session, context, &call).unwrap_or(Value::Null);
                match (submitter["how"].as_str(), submitter["x"].as_f64(), submitter["y"].as_f64()) {
                    (Some("click"), Some(x), Some(y)) => {
                        click_at(&mut session, x, y)?;
                        format!("clicked {}", json!(submitter["label"].as_str().unwrap_or("the button")))
                    }
                    _ => {
                        press_enter(&mut session).map_err(|e| (EXIT_UNAVAILABLE, e))?;
                        "pressed Enter".to_string()
                    }
                }
            }
        };
        match settle(&mut session, context, &frame_id, &url, password_len) {
            Settled::MovedOn => Ok(Some(how)),
            Settled::Stayed => Err(page(format!(
                "typed the login and {how}, but after 5 seconds the page still showed the password, so Mayi \
                 cleared it from the field. Look at the page: it may show an error, or need a button clicked; \
                 then run mayi fill again, with --submit-selector naming that button."
            ))),
        }
    });
    if outcome.is_err() {
        // Whatever went wrong, the password does not stay in the page.
        let _ = evaluate(&mut session, context, "mayiFill.clear('password')");
    }
    let _ = evaluate(&mut session, context, "mayiFill.forget()");
    let _ = write_frame(&mut writer, &ClientMsg::Done { exit: Some(if outcome.is_ok() { 0 } else { 1 }) });
    let submitted = outcome?;

    let names: Vec<&str> = wanted
        .iter()
        .map(|f| match *f {
            FIELD_TOTP => "two-factor code",
            other => other,
        })
        .collect();
    let what = match names.as_slice() {
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
        [] => String::new(),
    };
    let mut summary = format!("Typed the {what} of {} into {url}", login.name);
    match &submitted {
        Some(how) => summary.push_str(&format!(" and {how}.")),
        None => summary.push_str(", which submitted itself."),
    }
    thread::sleep(Duration::from_millis(700));
    if let Ok((_, now, _)) = frame(&mut session) {
        if now != url {
            summary.push_str(&format!(" The page is now {now}."));
        }
    }
    println!("{summary} Look at the page: if it asks for something else, such as a password or a code, run mayi fill again.");
    Ok(0)
}

/// Types each released value into its field, after checking the page is
/// still the one the user approved.
fn type_values(
    session: &mut Session,
    context: i64,
    frame_id: &str,
    origin: &Origin,
    values: &[(String, Zeroizing<String>)],
    code_boxes: usize,
    replies: &mpsc::Receiver<ServerMsg>,
) -> Result<(), Failure> {
    let (id, _, now) = frame(session)?;
    if id != frame_id || Origin::parse(&now).ok().as_ref() != Some(origin) {
        return Err(changed());
    }
    let fields: Vec<(&str, &Zeroizing<String>)> = [FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOTP]
        .into_iter()
        .filter_map(|field| values.iter().find(|(name, _)| name == field).map(|(_, value)| (field, value)))
        .collect();
    for (n, (field, value)) in fields.iter().enumerate() {
        if matches!(replies.try_recv(), Ok(ServerMsg::Stop)) {
            return Err((EXIT_DENIED, "stopped by the user".into()));
        }
        // Each digit of a split code goes in its own box.
        let parts: Vec<(&str, usize, Zeroizing<String>)> = match *field {
            FIELD_TOTP if code_boxes > 1 => {
                let digits: Vec<char> = value.chars().collect();
                if digits.len() != code_boxes {
                    return Err(page(format!(
                        "the page has {code_boxes} boxes for the code, and the code has {} digits",
                        digits.len()
                    )));
                }
                digits.iter().enumerate().map(|(i, d)| ("code", i, Zeroizing::new(d.to_string()))).collect()
            }
            FIELD_TOTP => vec![("code", 0, (*value).clone())],
            other => vec![(other, 0, (*value).clone())],
        };
        for (i, (name, index, text)) in parts.iter().enumerate() {
            let last = n + 1 == fields.len() && i + 1 == parts.len();
            if !type_into(session, context, name, *index, text)? && !last {
                return Err(page(format!(
                    "the page moved on after the {}; run mayi fill again on the new page",
                    label(name)
                )));
            }
        }
    }
    Ok(())
}

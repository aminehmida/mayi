//! Handles a run request from start to finish: policy, user interaction,
//! decryption, grants and the audit log.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use mayi_proto::site::{self, Origin};
use mayi_proto::{RunRequest, SecretInfo, FIELD_TOTP};
use zeroize::Zeroizing;

use crate::grants::{Grant, GrantScope, GrantStore};
use crate::model::{ItemMeta, Kind, Level, SecretValues};
use crate::policy::{self, Ctx, Rules, Verdict, Via};
use crate::totp::Totp;
use crate::vault::{AuditEntry, SecretUse, Vault};
use crate::{now_ms, Error};

/// The machine a request came from. Unlike the fields of [`RunRequest`],
/// this is established by the transport, not claimed by the requester.
#[derive(Clone, Debug)]
pub struct Requester {
    pub id: String,
    pub remote: bool,
}

pub struct PromptSecret {
    pub name: String,
    pub level: Level,
    pub needs_approval: bool,
}

/// What the user must see to decide. `request.reason`, `agent`, `session` and
/// `host` are written by the requesting side: show them as claims, and give
/// the command more weight. For a sign-in, `request.site` takes the place of
/// the command; it is also reported by the requesting side.
pub struct Prompt<'a> {
    pub run_id: u64,
    pub request: &'a RunRequest,
    pub requester: &'a Requester,
    pub secrets: Vec<PromptSecret>,
}

pub struct Notice<'a> {
    pub run_id: u64,
    pub request: &'a RunRequest,
    pub requester: &'a Requester,
    pub secrets: Vec<String>,
}

pub enum Approval {
    Deny,
    Allow(GrantScope),
}

/// The vault device's user interface.
pub trait Ui: Send + Sync {
    /// Blocks until the user answers, or until [`Ui::withdraw`] is called
    /// for the same run, in which case it should return [`Approval::Deny`].
    fn approve(&self, prompt: &Prompt) -> Approval;

    /// The requester went away while its prompt was showing: take the prompt
    /// down.
    fn withdraw(&self, _run_id: u64) {}

    /// Secrets were released without asking. The UI should offer a way to
    /// call [`Broker::stop`] with `notice.run_id`.
    fn notify(&self, notice: &Notice);

    /// A machine finished pairing and may now send requests.
    fn paired(&self, _name: &str, _id: &str) {}

    /// Another device joined the vault.
    fn device_added(&self, _name: &str) {}

    /// A sync with another device changed `_changed` records here.
    fn synced(&self, _changed: usize) {}

    /// The command of a released run ended, so its notice can go away.
    fn finished(&self, _run_id: u64, _exit: Option<i32>) {}

    /// Whether the owner is using this device right now (screen unlocked,
    /// recent input). Requesters ask the device in use first.
    fn user_active(&self) -> bool {
        false
    }

    /// Another machine just connected. A phone keeps itself awake for a
    /// moment so the request can arrive before it sleeps again.
    fn incoming(&self) {}
}

pub enum Outcome {
    Released {
        run_id: u64,
        env: BTreeMap<String, Zeroizing<String>>,
    },
    Denied(String),
}

pub struct Broker {
    vault: Vault,
    ui: Arc<dyn Ui>,
    rules: Rules,
    grants: Mutex<GrantStore>,
    /// Released runs whose command has not finished.
    active: Mutex<HashMap<u64, ActiveRun>>,
    /// Runs whose requester went away before a decision.
    withdrawn: Mutex<HashSet<u64>>,
    next_run: AtomicU64,
}

/// A released run whose command (or typing, for a sign-in) has not finished.
#[derive(Clone)]
struct ActiveRun {
    requester: String,
    session: String,
    /// The page's origin, for a sign-in.
    site: String,
}

struct Plan {
    meta: ItemMeta,
    level: Level,
    verdict: Verdict,
    grant: Option<Grant>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Broker {
    pub fn new(vault: Vault, ui: Arc<dyn Ui>, rules: Rules) -> Self {
        Self {
            vault,
            ui,
            rules,
            grants: Mutex::default(),
            active: Mutex::default(),
            withdrawn: Mutex::default(),
            next_run: AtomicU64::new(1),
        }
    }

    pub fn ui(&self) -> &dyn Ui {
        self.ui.as_ref()
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Names, levels and field names. Never values.
    pub fn list(&self) -> crate::Result<Vec<SecretInfo>> {
        Ok(self
            .vault
            .list()?
            .into_iter()
            .map(|m| SecretInfo {
                name: m.name,
                level: m.level as u8,
                fields: m.fields,
                login: m.kind == Kind::Login,
                sites: m.sites,
            })
            .collect())
    }

    /// Decides on a request and, if allowed, returns the environment to
    /// inject. Blocks while the user is being asked. Nothing is released
    /// unless the decision was written to the audit log.
    pub fn run(&self, request: &RunRequest, requester: &Requester) -> Outcome {
        self.run_reserved(self.reserve_run(), request, requester)
    }

    /// Allocates a run id ahead of [`Broker::run_reserved`], so the transport
    /// can call [`Broker::withdraw`] while the user is still being asked.
    pub fn reserve_run(&self) -> u64 {
        self.next_run.fetch_add(1, Ordering::Relaxed)
    }

    /// The requester went away before a decision: withdraw its prompt.
    pub fn withdraw(&self, run_id: u64) {
        lock(&self.withdrawn).insert(run_id);
        self.ui.withdraw(run_id);
    }

    pub fn run_reserved(&self, run_id: u64, request: &RunRequest, requester: &Requester) -> Outcome {
        let mut entry = AuditEntry {
            ts_ms: now_ms(),
            run_id,
            event: "request".into(),
            requester: requester.id.clone(),
            remote: requester.remote,
            agent: request.agent.clone(),
            session: request.session.clone(),
            host: request.host.clone(),
            cwd: request.cwd.clone(),
            argv: request.argv.clone(),
            site: request.site.clone().unwrap_or_default(),
            reason: request.reason.clone(),
            ..Default::default()
        };
        // Registered before the decision so a Stop pressed on a notice is
        // never too early.
        lock(&self.active).insert(
            run_id,
            ActiveRun {
                requester: requester.id.clone(),
                session: request.session.clone(),
                site: request.site.clone().unwrap_or_default(),
            },
        );
        let mut result = self.decide_and_reveal(run_id, request, requester, &mut entry);
        if lock(&self.withdrawn).remove(&run_id) {
            // Even if the user answered in the same instant, nobody is left
            // to receive the secret.
            result = Err("the requester went away".into());
        }
        entry.outcome = match &result {
            Ok(_) => "released".into(),
            Err(reason) => format!("denied: {reason}"),
        };
        if let Err(e) = self.vault.audit(&entry) {
            result = Err(format!("could not write the audit log: {e}"));
        }
        match result {
            Ok(env) => Outcome::Released { run_id, env },
            Err(reason) => {
                lock(&self.active).remove(&run_id);
                Outcome::Denied(reason)
            }
        }
    }

    fn decide_and_reveal(
        &self,
        run_id: u64,
        request: &RunRequest,
        requester: &Requester,
        entry: &mut AuditEntry,
    ) -> Result<BTreeMap<String, Zeroizing<String>>, String> {
        // A sign-in types one login into a page; anything else runs a command.
        let site = request.site.as_deref().map(Origin::parse).transpose()?;
        match &site {
            None if request.argv.is_empty() => return Err("no command given".into()),
            Some(_) if !request.argv.is_empty() => return Err("a sign-in cannot also run a command".into()),
            _ => {}
        }
        if request.bindings.is_empty() {
            return Err("no secrets requested".into());
        }
        if request.reason.trim().is_empty() {
            return Err("a reason is required".into());
        }

        // What grants are keyed on and allowlists matched against.
        let command = match &site {
            Some(origin) => format!("sign in to {origin}"),
            None => policy::command_line(&request.argv),
        };
        let ctx = Ctx { command: &command, remote: requester.remote };
        let now = now_ms();

        let mut plans: Vec<Plan> = Vec::new();
        for binding in &request.bindings {
            if plans.iter().any(|p| p.meta.name == binding.item) {
                continue;
            }
            let meta = self.vault.meta(&binding.item).map_err(|e| e.to_string())?;
            let grant = lock(&self.grants).find(
                &meta.id,
                meta.version,
                &requester.id,
                &request.session,
                &command,
                now,
            );
            let (level, verdict) = policy::decide(&meta, &ctx, &self.rules, grant.is_some());
            plans.push(Plan { meta, level, verdict, grant });
        }
        // Where the values may go is settled before anyone is asked: a login
        // never reaches a command, and never a page outside its websites.
        for plan in &plans {
            let name = &plan.meta.name;
            match (&site, plan.meta.kind) {
                (None, Kind::Login) => {
                    return Err(format!(
                        "{name} is a login: it can only be typed into its website, with `mayi fill`"
                    ))
                }
                (Some(_), Kind::Secret) => return Err(format!("{name} is not a login")),
                (Some(origin), Kind::Login) if !site::matches_any(&plan.meta.sites, origin) => {
                    return Err(format!("{name} is for {}, not {origin}", plan.meta.sites.join(", ")))
                }
                _ => {}
            }
        }
        if site.is_some() && plans.len() > 1 {
            return Err("a sign-in uses one login".into());
        }
        for binding in &request.bindings {
            let plan = plans.iter().find(|p| p.meta.name == binding.item).expect("planned above");
            if !plan.meta.fields.contains(&binding.field) {
                return Err(format!("secret {} has no field {}", binding.item, binding.field));
            }
        }
        entry.secrets = plans
            .iter()
            .map(|p| SecretUse {
                name: p.meta.name.clone(),
                level: p.level as u8,
                via: match p.verdict {
                    Verdict::Release { via: Via::Level, .. } => "level",
                    Verdict::Release { via: Via::Allowlist, .. } => "allowlist",
                    Verdict::Release { via: Via::Grant, .. } => "grant",
                    Verdict::Prompt => "approval",
                    Verdict::Biometric => "biometric",
                }
                .into(),
            })
            .collect();

        // One prompt covers every secret that needs approval.
        let mut scope = GrantScope::Once;
        if plans.iter().any(|p| p.verdict == Verdict::Prompt) {
            let prompt = Prompt {
                run_id,
                request,
                requester,
                secrets: plans
                    .iter()
                    .map(|p| PromptSecret {
                        name: p.meta.name.clone(),
                        level: p.level,
                        needs_approval: p.verdict == Verdict::Prompt,
                    })
                    .collect(),
            };
            match self.ui.approve(&prompt) {
                Approval::Allow(s) => scope = s,
                Approval::Deny => return Err("denied by the user".into()),
            }
        }

        // Level 4 secrets not covered by a grant: one biometric check for all.
        // Everything else is readable with the vault key.
        let (biometric, plain): (Vec<&Plan>, Vec<&Plan>) = plans
            .iter()
            .filter(|p| p.grant.as_ref().is_none_or(|g| g.values.is_none()))
            .partition(|p| p.verdict == Verdict::Biometric);
        let mut values: HashMap<&str, SecretValues> = HashMap::new();
        for plan in &plans {
            if let Some(cached) = plan.grant.as_ref().and_then(|g| g.values.clone()) {
                values.insert(&plan.meta.name, cached);
            }
        }
        for (group, text) in [
            (&biometric, biometric_prompt(site.as_ref(), request, requester, &biometric)),
            (&plain, String::new()),
        ] {
            if group.is_empty() {
                continue;
            }
            let metas: Vec<&ItemMeta> = group.iter().map(|p| &p.meta).collect();
            let revealed = self.vault.reveal(&metas, &text).map_err(|e| match e {
                Error::BiometricDenied => "biometric check failed or was cancelled".to_string(),
                other => other.to_string(),
            })?;
            for (plan, v) in group.iter().zip(revealed) {
                values.insert(&plan.meta.name, v);
            }
        }

        let mut env = BTreeMap::new();
        for binding in &request.bindings {
            let value = values
                .get(binding.item.as_str())
                .and_then(|v| v.get(&binding.field))
                .ok_or_else(|| format!("secret {} has no field {}", binding.item, binding.field))?;
            // The two-factor key stays here: the page gets the current code.
            let value = if binding.field == FIELD_TOTP && site.is_some() {
                let now_secs = now_ms() / 1000;
                Totp::parse(value).map_err(|e| format!("{}: {e}", binding.item))?.code(now_secs)
            } else {
                value.clone()
            };
            env.insert(binding.env.clone(), value);
        }

        let mut grants = lock(&self.grants);
        for plan in &plans {
            let (covers_any_command, window_secs, cached) = match plan.verdict {
                Verdict::Prompt if scope != GrantScope::Once => {
                    (scope == GrantScope::SessionAny, plan.meta.max_grant_secs, None)
                }
                // One approval covers the next pages of the same sign-in.
                Verdict::Prompt if site.is_some() => {
                    (false, plan.meta.max_grant_secs.min(self.rules.sign_in_window_secs), None)
                }
                Verdict::Biometric => (
                    false,
                    plan.meta.max_grant_secs.min(self.rules.biometric_window_secs),
                    values.get(plan.meta.name.as_str()).cloned(),
                ),
                _ => continue,
            };
            if window_secs == 0 {
                continue;
            }
            grants.add(Grant {
                id: 0,
                item_id: plan.meta.id.clone(),
                item_version: plan.meta.version,
                requester: requester.id.clone(),
                session: request.session.clone(),
                command: (!covers_any_command).then(|| command.clone()),
                expires_at_ms: now_ms() + window_secs * 1000,
                values: cached,
            });
        }
        drop(grants);

        let notified: Vec<String> = plans
            .iter()
            .filter(|p| matches!(p.verdict, Verdict::Release { notify: true, .. }))
            .map(|p| p.meta.name.clone())
            .collect();
        if !notified.is_empty() {
            self.ui.notify(&Notice { run_id, request, requester, secrets: notified });
        }
        Ok(env)
    }

    /// The user pressed Stop on a released run: revoke every grant of that
    /// session. The caller is responsible for telling the requester to kill
    /// the command. Returns false if the run is unknown or already finished.
    pub fn stop(&self, run_id: u64) -> bool {
        let Some(ActiveRun { requester, session, site }) = lock(&self.active).get(&run_id).cloned() else {
            return false;
        };
        let revoked = lock(&self.grants).revoke_session(&requester, &session);
        let _ = self.vault.audit(&AuditEntry {
            ts_ms: now_ms(),
            run_id,
            event: "stop".into(),
            outcome: format!("stopped by the user, {revoked} grant(s) revoked"),
            requester,
            session,
            site,
            ..Default::default()
        });
        true
    }

    /// The command of a released run ended (`exit` is `None` if the requester
    /// went away without reporting).
    pub fn finished(&self, run_id: u64, exit: Option<i32>) {
        let Some(ActiveRun { requester, session, site }) = lock(&self.active).remove(&run_id) else {
            return;
        };
        self.ui.finished(run_id, exit);
        let _ = self.vault.audit(&AuditEntry {
            ts_ms: now_ms(),
            run_id,
            event: "exit".into(),
            outcome: match exit {
                Some(code) => format!("exit {code}"),
                None => "requester disconnected".into(),
            },
            requester,
            session,
            site,
            ..Default::default()
        });
    }
}

fn biometric_prompt(site: Option<&Origin>, request: &RunRequest, requester: &Requester, plans: &[&Plan]) -> String {
    let names: Vec<&str> = plans.iter().map(|p| p.meta.name.as_str()).collect();
    match site {
        Some(origin) => format!("Sign in to {origin} with {} on {}", names.join(", "), requester.id),
        None => format!(
            "Unlock {} for `{}` on {}",
            names.join(", "),
            policy::command_line(&request.argv),
            requester.id
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::SoftwareKeys;
    use crate::model::NewItem;
    use mayi_proto::Binding;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    #[derive(Default)]
    struct FakeUi {
        answer: Mutex<Option<GrantScope>>,
        prompts: AtomicUsize,
        notices: AtomicUsize,
    }

    impl Ui for FakeUi {
        fn approve(&self, _: &Prompt) -> Approval {
            self.prompts.fetch_add(1, Ordering::SeqCst);
            match *lock(&self.answer) {
                Some(scope) => Approval::Allow(scope),
                None => Approval::Deny,
            }
        }

        fn notify(&self, _: &Notice) {
            self.notices.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Fixture {
        broker: Broker,
        ui: Arc<FakeUi>,
        biometric_ok: Arc<AtomicBool>,
        biometric_checks: Arc<AtomicUsize>,
        _dir: tempfile::TempDir,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let biometric_ok = Arc::new(AtomicBool::new(true));
        let biometric_checks = Arc::new(AtomicUsize::new(0));
        let (ok, checks) = (biometric_ok.clone(), biometric_checks.clone());
        let keys = SoftwareKeys::generate(move |_| {
            checks.fetch_add(1, Ordering::SeqCst);
            ok.load(Ordering::SeqCst)
        });
        let vault = Vault::create(&dir.path().join("v.db"), Arc::new(keys), "test").unwrap();
        for (name, level, allow) in [
            ("L1", Level::Log, vec![]),
            ("L2", Level::Notify, vec![]),
            ("L3", Level::Approve, vec![]),
            ("L3_MAKE", Level::Approve, vec!["make *".to_string()]),
            ("L4", Level::Biometric, vec![]),
        ] {
            vault
                .put(NewItem {
                    name: name.into(),
                    level,
                    values: [("value".to_string(), Zeroizing::new(format!("{name}-secret")))]
                        .into_iter()
                        .collect(),
                    allow,
                    max_grant_secs: 600,
                    kind: Kind::Secret,
                    sites: vec![],
                })
                .unwrap();
        }
        for (name, level) in [("GH", Level::Approve), ("GH4", Level::Biometric)] {
            vault
                .put(NewItem {
                    name: name.into(),
                    level,
                    values: [("username", "amine"), ("password", "hunter2"), ("totp", TOTP_KEY)]
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
                        .collect(),
                    allow: vec![],
                    max_grant_secs: 600,
                    kind: Kind::Login,
                    sites: vec!["github.com".into(), "*.github.com".into()],
                })
                .unwrap();
        }
        let ui = Arc::new(FakeUi::default());
        let broker = Broker::new(vault, ui.clone(), Rules::default());
        Fixture { broker, ui, biometric_ok, biometric_checks, _dir: dir }
    }

    fn request(items: &[&str], command: &str, session: &str) -> RunRequest {
        RunRequest {
            bindings: items
                .iter()
                .map(|i| Binding { env: format!("ENV_{i}"), item: i.to_string(), field: "value".into() })
                .collect(),
            argv: command.split(' ').map(String::from).collect(),
            reason: "testing".into(),
            session: session.into(),
            ..Default::default()
        }
    }

    const TOTP_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn sign_in(item: &str, site: &str, fields: &[&str], session: &str) -> RunRequest {
        RunRequest {
            bindings: fields
                .iter()
                .map(|f| Binding { env: f.to_string(), item: item.into(), field: f.to_string() })
                .collect(),
            site: Some(site.into()),
            reason: "testing".into(),
            session: session.into(),
            ..Default::default()
        }
    }

    fn local() -> Requester {
        Requester { id: "local".into(), remote: false }
    }

    fn released(outcome: Outcome) -> BTreeMap<String, Zeroizing<String>> {
        match outcome {
            Outcome::Released { env, .. } => env,
            Outcome::Denied(reason) => panic!("denied: {reason}"),
        }
    }

    fn denied(outcome: Outcome) -> String {
        match outcome {
            Outcome::Denied(reason) => reason,
            Outcome::Released { .. } => panic!("released"),
        }
    }

    #[test]
    fn level_1_is_silent_and_logged() {
        let f = fixture();
        let env = released(f.broker.run(&request(&["L1"], "make test", "s"), &local()));
        assert_eq!(&**env.get("ENV_L1").unwrap(), "L1-secret");
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 0);
        assert_eq!(f.ui.notices.load(Ordering::SeqCst), 0);
        let log = f.broker.vault().audit_tail(10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].outcome, "released");
        assert_eq!(log[0].reason, "testing");
        assert_eq!(log[0].secrets[0].name, "L1");
        assert!(!serde_json::to_string(&log).unwrap().contains("L1-secret"));
    }

    #[test]
    fn level_2_notifies_and_remote_raises_level_1() {
        let f = fixture();
        released(f.broker.run(&request(&["L2"], "x", "s"), &local()));
        assert_eq!(f.ui.notices.load(Ordering::SeqCst), 1);
        let remote = Requester { id: "vm".into(), remote: true };
        released(f.broker.run(&request(&["L1"], "x", "s"), &remote));
        assert_eq!(f.ui.notices.load(Ordering::SeqCst), 2);
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn level_3_deny_and_once() {
        let f = fixture();
        assert_eq!(
            denied(f.broker.run(&request(&["L3"], "x", "s"), &local())),
            "denied by the user"
        );
        *lock(&f.ui.answer) = Some(GrantScope::Once);
        released(f.broker.run(&request(&["L3"], "x", "s"), &local()));
        released(f.broker.run(&request(&["L3"], "x", "s"), &local()));
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 3, "once means asking every time");
        let log = f.broker.vault().audit_tail(10).unwrap();
        assert_eq!(log[0].outcome, "denied: denied by the user");
    }

    #[test]
    fn level_3_session_grants() {
        let f = fixture();
        *lock(&f.ui.answer) = Some(GrantScope::SessionCommand);
        released(f.broker.run(&request(&["L3"], "make a", "s"), &local()));
        released(f.broker.run(&request(&["L3"], "make a", "s"), &local()));
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 1);
        released(f.broker.run(&request(&["L3"], "make b", "s"), &local()));
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 2, "other command asks again");
        released(f.broker.run(&request(&["L3"], "make a", "other"), &local()));
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 3, "other session asks again");

        *lock(&f.ui.answer) = Some(GrantScope::SessionAny);
        released(f.broker.run(&request(&["L3"], "x", "any"), &local()));
        *lock(&f.ui.answer) = None;
        released(f.broker.run(&request(&["L3"], "y", "any"), &local()));
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn allowlist_skips_prompt_only_for_matching_command() {
        let f = fixture();
        released(f.broker.run(&request(&["L3_MAKE"], "make deploy", "s"), &local()));
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 0);
        assert_eq!(f.ui.notices.load(Ordering::SeqCst), 1);
        denied(f.broker.run(&request(&["L3_MAKE"], "curl evil.example", "s"), &local()));
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn level_4_checks_biometrics_and_caches_per_command() {
        let f = fixture();
        f.biometric_ok.store(false, Ordering::SeqCst);
        assert_eq!(
            denied(f.broker.run(&request(&["L4"], "deploy", "s"), &local())),
            "biometric check failed or was cancelled"
        );
        f.biometric_ok.store(true, Ordering::SeqCst);
        f.biometric_checks.store(0, Ordering::SeqCst);

        let env = released(f.broker.run(&request(&["L4"], "deploy", "s"), &local()));
        assert_eq!(&**env.get("ENV_L4").unwrap(), "L4-secret");
        let env = released(f.broker.run(&request(&["L4"], "deploy", "s"), &local()));
        assert_eq!(&**env.get("ENV_L4").unwrap(), "L4-secret");
        assert_eq!(f.biometric_checks.load(Ordering::SeqCst), 1, "window covers the repeat");

        released(f.broker.run(&request(&["L4"], "other", "s"), &local()));
        assert_eq!(f.biometric_checks.load(Ordering::SeqCst), 2, "other command checks again");
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn mixed_request_asks_once_for_each_kind() {
        let f = fixture();
        *lock(&f.ui.answer) = Some(GrantScope::Once);
        let env = released(f.broker.run(&request(&["L1", "L2", "L3", "L4"], "x", "s"), &local()));
        assert_eq!(env.len(), 4);
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 1);
        assert_eq!(f.ui.notices.load(Ordering::SeqCst), 1);
        assert_eq!(f.biometric_checks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn stop_revokes_the_session() {
        let f = fixture();
        *lock(&f.ui.answer) = Some(GrantScope::SessionAny);
        let Outcome::Released { run_id, .. } = f.broker.run(&request(&["L3"], "x", "s"), &local())
        else {
            panic!("denied")
        };
        assert!(f.broker.stop(run_id));
        *lock(&f.ui.answer) = None;
        denied(f.broker.run(&request(&["L3"], "x", "s"), &local()));
        f.broker.finished(run_id, Some(143));
        assert!(!f.broker.stop(run_id), "finished runs cannot be stopped");
        let events: Vec<String> =
            f.broker.vault().audit_tail(10).unwrap().into_iter().map(|e| e.event).collect();
        assert_eq!(events, ["request", "stop", "request", "exit"]);
    }

    #[test]
    fn withdrawn_run_is_denied_whatever_the_answer() {
        let f = fixture();
        *lock(&f.ui.answer) = Some(GrantScope::SessionAny);
        let run_id = f.broker.reserve_run();
        f.broker.withdraw(run_id);
        assert_eq!(
            denied(f.broker.run_reserved(run_id, &request(&["L3"], "x", "s"), &local())),
            "the requester went away"
        );
        let log = f.broker.vault().audit_tail(1).unwrap();
        assert_eq!(log[0].outcome, "denied: the requester went away");
    }

    #[test]
    fn sign_in_releases_the_code_and_never_the_key() {
        let f = fixture();
        *lock(&f.ui.answer) = Some(GrantScope::Once);
        let request = sign_in("GH", "https://github.com/login", &["username", "password", "totp"], "s");
        let env = released(f.broker.run(&request, &local()));
        assert_eq!(&**env.get("username").unwrap(), "amine");
        assert_eq!(&**env.get("password").unwrap(), "hunter2");
        let code = env.get("totp").unwrap();
        assert!(code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()), "a code, not the key");
        let log = f.broker.vault().audit_tail(1).unwrap();
        assert_eq!(log[0].site, "https://github.com/login");
        assert_eq!(log[0].outcome, "released");
        f.broker.finished(log[0].run_id, Some(0));
        let exit = &f.broker.vault().audit_tail(1).unwrap()[0];
        assert_eq!((exit.event.as_str(), exit.site.as_str()), ("exit", "https://github.com/login"), "the exit says it was a sign-in");
        let text = serde_json::to_string(&log).unwrap();
        for value in ["hunter2", TOTP_KEY, code.as_str()] {
            assert!(!text.contains(value), "the audit log holds no value");
        }
    }

    #[test]
    fn a_login_goes_only_to_its_websites() {
        let f = fixture();
        *lock(&f.ui.answer) = Some(GrantScope::SessionAny);
        for site in ["https://github.com.evil.example", "https://evilgithub.com", "https://github.com:8443"] {
            let reason = denied(f.broker.run(&sign_in("GH", site, &["password"], "s"), &local()));
            assert!(reason.starts_with("GH is for github.com, *.github.com, not"), "{reason}");
        }
        let reason = denied(f.broker.run(&sign_in("GH", "http://github.com", &["password"], "s"), &local()));
        assert!(reason.contains("plain http"), "{reason}");
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 0, "refused before anyone is asked");
        assert!(f.broker.vault().audit_tail(1).unwrap()[0].outcome.starts_with("denied: "));
    }

    #[test]
    fn logins_and_commands_do_not_mix() {
        let f = fixture();
        *lock(&f.ui.answer) = Some(GrantScope::SessionAny);
        let reason = denied(f.broker.run(&request(&["GH"], "env", "s"), &local()));
        assert!(reason.contains("GH is a login"), "{reason}");
        let mut bound = request(&["GH"], "env", "s");
        bound.bindings[0].field = "password".into();
        assert!(denied(f.broker.run(&bound, &local())).contains("is a login"));

        let secret = RunRequest {
            bindings: vec![Binding { env: "value".into(), item: "L1".into(), field: "value".into() }],
            ..sign_in("GH", "https://github.com", &[], "s")
        };
        assert_eq!(denied(f.broker.run(&secret, &local())), "L1 is not a login");
        let with_command = RunRequest { argv: vec!["env".into()], ..sign_in("GH", "https://github.com", &["password"], "s") };
        assert_eq!(denied(f.broker.run(&with_command, &local())), "a sign-in cannot also run a command");
        let mut two = sign_in("GH", "https://github.com", &["password"], "s");
        two.bindings.push(Binding { env: "other".into(), item: "GH4".into(), field: "password".into() });
        assert_eq!(denied(f.broker.run(&two, &local())), "a sign-in uses one login");
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn one_approval_covers_a_sign_in_over_several_pages() {
        let f = fixture();
        *lock(&f.ui.answer) = Some(GrantScope::Once);
        for field in ["username", "password", "totp"] {
            released(f.broker.run(&sign_in("GH", "https://github.com", &[field], "s"), &local()));
        }
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 1);
        released(f.broker.run(&sign_in("GH", "https://gist.github.com", &["password"], "s"), &local()));
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 2, "another site asks again");
        released(f.broker.run(&sign_in("GH", "https://github.com", &["password"], "other"), &local()));
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 3, "another session asks again");
    }

    #[test]
    fn level_4_sign_in_asks_for_one_fingerprint() {
        let f = fixture();
        for field in ["username", "password", "totp"] {
            let env = released(f.broker.run(&sign_in("GH4", "https://github.com", &[field], "s"), &local()));
            assert_ne!(&**env.get(field).unwrap(), TOTP_KEY);
        }
        assert_eq!(f.biometric_checks.load(Ordering::SeqCst), 1);
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn malformed_requests_are_denied() {
        let f = fixture();
        let mut no_reason = request(&["L1"], "x", "s");
        no_reason.reason = "  ".into();
        assert_eq!(denied(f.broker.run(&no_reason, &local())), "a reason is required");
        assert_eq!(
            denied(f.broker.run(&request(&["NOPE"], "x", "s"), &local())),
            "no such secret: NOPE"
        );
        let mut bad_field = request(&["L1"], "x", "s");
        bad_field.bindings[0].field = "missing".into();
        assert_eq!(
            denied(f.broker.run(&bad_field, &local())),
            "secret L1 has no field missing"
        );
        let mut no_command = request(&["L1"], "x", "s");
        no_command.argv.clear();
        assert_eq!(denied(f.broker.run(&no_command, &local())), "no command given");
    }
}

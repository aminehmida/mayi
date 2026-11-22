//! Handles a run request from start to finish: policy, user interaction,
//! decryption, grants and the audit log.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use mayi_proto::site::{self, Origin};
use mayi_proto::{AwsInfo, ProfileInfo, RunRequest, SecretInfo};
use zeroize::Zeroizing;

use crate::aws::{self, AwsProvider};
use crate::grants::{Grant, GrantScope, GrantStore};
use crate::model::{AwsProfile, Destination, ItemMeta, Level, SecretValues, Source};
use crate::policy::{self, Ctx, Rules, Verdict, Via};
use crate::provider::{self, Provider, Refusal, Release};
use crate::vault::{AuditEntry, SecretUse, Vault};
use crate::{now_ms, Error};

/// The machine a request came from. Unlike the fields of [`RunRequest`],
/// this is established by the transport, not claimed by the requester.
/// Why a run whose requester stopped waiting was not released: it was
/// answered on another device, or the agent gave up.
pub const WITHDRAWN: &str = "withdrawn: answered on another device, or the agent stopped waiting";

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

/// An AWS sign-in a request needs has ended: the owner can sign in again
/// and the request carries on.
pub struct SignInNeeded<'a> {
    pub run_id: u64,
    pub request: &'a RunRequest,
    pub requester: &'a Requester,
    /// The sign-in, by name.
    pub name: &'a str,
    pub start_url: &'a str,
    pub region: &'a str,
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

    /// An AWS sign-in ended while a request needed it. Blocks while the
    /// owner signs in again (the app saves the new session with
    /// [`Vault::renew_aws`]); returns whether they did. Withdrawing the run
    /// should make it return false.
    fn sign_in(&self, _needed: &SignInNeeded) -> bool {
        false
    }
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
    aws: AwsProvider,
    grants: Mutex<GrantStore>,
    /// The run whose biometric check is showing, so withdrawing that run
    /// takes the check down too.
    biometric_run: Mutex<Option<u64>>,
    /// Sessions already told that a level 1 secret is used from another
    /// machine: told once per session, not at every use.
    noticed: Mutex<HashSet<(String, String, String)>>,
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

struct Plan<'a> {
    meta: ItemMeta,
    provider: &'a dyn Provider,
    /// For an AWS sign-in: the profile requested.
    profile: Option<AwsProfile>,
    /// The level before context: the profile's, or the secret's.
    base: Level,
    level: Level,
    verdict: Verdict,
    /// What grants are kept under: the secret, or one profile of a sign-in
    /// at its level, so approving read-only never covers admin.
    grant_key: (String, u64),
    grant: Option<Grant>,
}

impl Plan<'_> {
    /// The secret as the owner knows it: `mawaqit/production-ro` for a
    /// profile.
    fn shown(&self) -> String {
        match &self.profile {
            Some(p) => format!("{}/{}", self.meta.name, p.name),
            None => self.meta.name.clone(),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Broker {
    pub fn new(vault: Vault, ui: Arc<dyn Ui>, rules: Rules) -> Self {
        Self::with_aws(vault, ui, rules, Arc::new(aws::HttpApi::default()))
    }

    /// A broker that reaches AWS through `api`: a stand-in in tests.
    pub fn with_aws(vault: Vault, ui: Arc<dyn Ui>, rules: Rules, api: Arc<dyn aws::Api>) -> Self {
        Self {
            vault,
            ui,
            rules,
            aws: AwsProvider::new(api),
            noticed: Mutex::default(),
            biometric_run: Mutex::default(),
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

    /// Releases AWS sign-ins; also lists a sign-in's accounts for the apps.
    pub fn aws(&self) -> &AwsProvider {
        &self.aws
    }

    /// The accounts and roles an AWS sign-in reaches, to add profiles
    /// without signing in again.
    pub fn aws_accounts(&self, name: &str) -> Result<Vec<aws::Account>, String> {
        let meta = self.vault.meta(name).map_err(|e| e.to_string())?;
        let stored = self.vault.reveal(&[&meta], "").map_err(|e| e.to_string())?.remove(0);
        let (accounts, store) = self.aws.accounts(&meta, &stored).map_err(|e| match e {
            Refusal::SignInNeeded(why) => format!("{why}: sign in again"),
            Refusal::Failed(why) => why,
        })?;
        if let Some(values) = store {
            let _ = self.vault.store_values(&meta, &values);
        }
        Ok(accounts)
    }

    fn provider(&self, meta: &ItemMeta) -> Result<&dyn Provider, String> {
        provider::check_known(meta)?;
        match meta.source {
            Source::AwsSso => Ok(&self.aws),
            _ => provider::stored(&meta.destination).map_err(|e| format!("{}: {e}", meta.name)),
        }
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
                login: m.destination == Destination::Website,
                sites: m.sites,
                aws: m.aws.map(|a| AwsInfo {
                    start_url: a.start_url,
                    region: a.region,
                    profiles: a
                        .profiles
                        .into_iter()
                        .map(|p| ProfileInfo {
                            name: p.name,
                            level: p.level as u8,
                            account_id: p.account_id,
                            account_name: p.account_name,
                            role: p.role,
                        })
                        .collect(),
                }),
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
        // Answered elsewhere: a fingerprint dialog for it must not stay up.
        if *lock(&self.biometric_run) == Some(run_id) {
            self.vault.cancel_biometric();
        }
    }

    /// Runs a biometric check for `run_id`, so that withdrawing the run
    /// takes it down. A run already withdrawn is not asked at all.
    fn biometric<T>(&self, run_id: u64, check: impl FnOnce() -> crate::Result<T>) -> Result<T, String> {
        *lock(&self.biometric_run) = Some(run_id);
        let result = if lock(&self.withdrawn).contains(&run_id) {
            Err(WITHDRAWN.to_string())
        } else {
            check().map_err(|e| match e {
                Error::BiometricDenied => "biometric check failed or was cancelled".to_string(),
                other => other.to_string(),
            })
        };
        *lock(&self.biometric_run) = None;
        result
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
            // What ran: the program by its full path when the requester sent it.
            argv: request.shown_argv(),
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
        let withdrawn = lock(&self.withdrawn).remove(&run_id);
        if withdrawn {
            // Even if the user answered in the same instant, nobody is left
            // to receive the secret.
            result = Err(WITHDRAWN.into());
        }
        entry.outcome = match &result {
            // Not refused: answered on another device, or no longer waited for.
            _ if withdrawn => "withdrawn".into(),
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
            None => policy::command_line(&request.shown_argv()),
        };
        let by_name = site.is_none().then(|| policy::command_by_name(request)).flatten();
        let ctx = Ctx { command: &command, by_name: by_name.as_deref(), remote: requester.remote };
        let now = now_ms();
        let fields_of = |item: &str| -> Vec<&str> {
            request.bindings.iter().filter(|b| b.item == item).map(|b| b.field.as_str()).collect()
        };

        let mut plans: Vec<Plan> = Vec::new();
        for binding in &request.bindings {
            if plans.iter().any(|p| p.meta.name == binding.item) {
                continue;
            }
            let meta = self.vault.meta(&binding.item).map_err(|e| e.to_string())?;
            // Refused before anyone is asked: this device could not release it.
            let provider = self.provider(&meta)?;
            let profile = match meta.source {
                Source::AwsSso => Some(aws::requested_profile(&meta, &fields_of(&meta.name))?.clone()),
                _ => None,
            };
            let base = profile.as_ref().map_or(meta.level, |p| p.level);
            let grant_key = match &profile {
                // The sign-in's own version changes when AWS replaces a
                // token; the profile's level is part of the key instead.
                Some(p) => (format!("{}#{}#{}#{}", meta.id, p.account_id, p.role, p.level as u8), 0),
                None => (meta.id.clone(), meta.version),
            };
            let grant = lock(&self.grants).find(&grant_key.0, grant_key.1, &requester.id, &request.session, &command, now);
            let (level, verdict) = policy::decide(&meta, base, &ctx, &self.rules, grant.is_some());
            plans.push(Plan { meta, provider, profile, base, level, verdict, grant_key, grant });
        }
        // Where the values may go is settled before anyone is asked: a login
        // never reaches a command, and never a page outside its websites.
        for plan in &plans {
            let name = &plan.meta.name;
            match (&site, &plan.meta.destination) {
                (None, Destination::Website) => {
                    return Err(format!(
                        "{name} is a login: it can only be typed into its website, with `mayi fill`"
                    ))
                }
                (Some(_), Destination::Command) => return Err(format!("{name} is not a login")),
                (Some(origin), Destination::Website) if !site::matches_any(&plan.meta.sites, origin) => {
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
            // An AWS sign-in's fields were checked with its profile.
            if plan.profile.is_none() && !plan.meta.fields.contains(&binding.field) {
                return Err(format!("secret {} has no field {}", binding.item, binding.field));
            }
        }
        entry.secrets = plans
            .iter()
            .map(|p| SecretUse {
                name: p.shown(),
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
                        name: p.shown(),
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

        // A level 4 AWS profile: the sign-in is not encrypted to the
        // fingerprint (every profile shares it), so the fingerprint is asked
        // through the same hardware key, as proof of presence.
        let presence: Vec<&Plan> = plans
            .iter()
            .filter(|p| p.verdict == Verdict::Biometric && p.meta.level != Level::Biometric)
            .collect();
        if !presence.is_empty() {
            let names: Vec<String> = presence.iter().map(|p| p.shown()).collect();
            let text = biometric_prompt(site.as_ref(), request, requester, &names);
            self.biometric(run_id, || self.vault.confirm_presence(&text))?;
        }

        // Level 4 secrets not covered by a grant: one biometric check for all.
        // Everything else is readable with the vault key.
        let (biometric, plain): (Vec<&Plan>, Vec<&Plan>) = plans
            .iter()
            .filter(|p| p.grant.as_ref().is_none_or(|g| g.values.is_none()))
            .partition(|p| p.verdict == Verdict::Biometric && p.meta.level == Level::Biometric);
        let mut values: HashMap<&str, SecretValues> = HashMap::new();
        for plan in &plans {
            if let Some(cached) = plan.grant.as_ref().and_then(|g| g.values.clone()) {
                values.insert(&plan.meta.name, cached);
            }
        }
        let biometric_names: Vec<String> = biometric.iter().map(|p| p.shown()).collect();
        for (group, text) in [
            (&biometric, biometric_prompt(site.as_ref(), request, requester, &biometric_names)),
            (&plain, String::new()),
        ] {
            if group.is_empty() {
                continue;
            }
            let metas: Vec<&ItemMeta> = group.iter().map(|p| &p.meta).collect();
            let revealed = self.biometric(run_id, || self.vault.reveal(&metas, &text))?;
            for (plan, v) in group.iter().zip(revealed) {
                values.insert(&plan.meta.name, v);
            }
        }

        // Each provider makes what is released from what is stored: a
        // login's two-factor key stays here and the page gets the code; an
        // AWS sign-in's session stays here and the command gets one role.
        let now_secs = now_ms() / 1000;
        let mut released: HashMap<String, SecretValues> = HashMap::new();
        for plan in &plans {
            let name = plan.meta.name.as_str();
            let fields = fields_of(name);
            let stored = values.get(name).ok_or_else(|| format!("{name} could not be opened"))?;
            let out = self.release(run_id, request, requester, plan, stored, &fields, now_secs)?;
            released.insert(name.to_string(), out);
        }
        let mut env = BTreeMap::new();
        for binding in &request.bindings {
            let value = released
                .get(binding.item.as_str())
                .and_then(|v| v.get(&binding.field))
                .ok_or_else(|| format!("secret {} has no field {}", binding.item, binding.field))?;
            env.insert(binding.env.clone(), value.clone());
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
                    // Values kept only where they were encrypted to the
                    // fingerprint; an AWS profile fetches again.
                    (plan.meta.level == Level::Biometric).then(|| values.get(plan.meta.name.as_str()).cloned()).flatten(),
                ),
                _ => continue,
            };
            if window_secs == 0 {
                continue;
            }
            grants.add(Grant {
                id: 0,
                item_id: plan.grant_key.0.clone(),
                item_version: plan.grant_key.1,
                requester: requester.id.clone(),
                session: request.session.clone(),
                command: (!covers_any_command).then(|| command.clone()),
                expires_at_ms: now_ms() + window_secs * 1000,
                values: cached,
            });
        }
        drop(grants);

        let mut noticed = lock(&self.noticed);
        let notified: Vec<String> = plans
            .iter()
            .filter(|p| matches!(p.verdict, Verdict::Release { notify: true, .. }))
            .filter(|p| {
                // Level 1, raised only because the request is remote: once
                // per session, not at every `aws` call.
                let raised = p.base == Level::Log && requester.remote;
                !raised || noticed.insert((requester.id.clone(), request.session.clone(), p.grant_key.0.clone()))
            })
            .map(|p| p.shown())
            .collect();
        drop(noticed);
        if !notified.is_empty() {
            self.ui.notify(&Notice { run_id, request, requester, secrets: notified });
        }
        Ok(env)
    }

    /// Asks a plan's provider for its values. An AWS sign-in that ended is
    /// signed in again through the app, if the owner wants, and asked once
    /// more; a refresh token AWS replaced is kept.
    #[allow(clippy::too_many_arguments)]
    fn release(
        &self,
        run_id: u64,
        request: &RunRequest,
        requester: &Requester,
        plan: &Plan,
        stored: &SecretValues,
        fields: &[&str],
        now_secs: u64,
    ) -> Result<SecretValues, String> {
        let shown = plan.shown();
        let mut meta = plan.meta.clone();
        let mut stored = stored.clone();
        let mut signed_in_again = false;
        loop {
            let asked = Release { meta: &meta, stored: &stored, fields, now_secs };
            match plan.provider.release(&asked) {
                Ok(out) => {
                    if let Some(values) = out.store {
                        // Kept in memory regardless; storing lets the other
                        // devices and the next start use the new token.
                        let _ = self.vault.store_values(&meta, &values);
                    }
                    return Ok(out.values);
                }
                Err(Refusal::SignInNeeded(why)) if !signed_in_again => {
                    let aws = meta.aws.clone().unwrap_or_default();
                    let needed = SignInNeeded {
                        run_id,
                        request,
                        requester,
                        name: &meta.name,
                        start_url: &aws.start_url,
                        region: &aws.region,
                    };
                    if lock(&self.withdrawn).contains(&run_id) || !self.ui.sign_in(&needed) {
                        return Err(format!("{shown}: {why}. Sign in again in Mayi, then retry"));
                    }
                    signed_in_again = true;
                    self.aws.forget(&meta.id);
                    meta = self.vault.meta(&meta.name).map_err(|e| e.to_string())?;
                    stored = self.vault.reveal(&[&meta], "").map_err(|e| e.to_string())?.remove(0);
                }
                Err(e) => return Err(format!("{shown}: {e}")),
            }
        }
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

fn biometric_prompt(site: Option<&Origin>, request: &RunRequest, requester: &Requester, names: &[String]) -> String {
    match site {
        Some(origin) => format!("Sign in to {origin} with {} on {}", names.join(", "), requester.id),
        None => format!(
            "Unlock {} for `{}` on {}",
            names.join(", "),
            policy::command_line(&request.shown_argv()),
            requester.id
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aws::fake::FakeAws;
    use crate::hardware::SoftwareKeys;
    use crate::model::{AwsSignIn, NewItem, Source};
    use mayi_proto::Binding;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    #[derive(Default)]
    struct FakeUi {
        answer: Mutex<Option<GrantScope>>,
        prompts: AtomicUsize,
        notices: AtomicUsize,
        sign_ins: AtomicUsize,
        /// When set, "signing in again" brings this AWS session back.
        revive: Mutex<Option<Arc<FakeAws>>>,
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

        fn sign_in(&self, needed: &SignInNeeded) -> bool {
            assert_eq!(needed.start_url, "https://mawaqit.awsapps.com/start");
            self.sign_ins.fetch_add(1, Ordering::SeqCst);
            match &*lock(&self.revive) {
                Some(api) => {
                    api.session_alive.store(true, Ordering::SeqCst);
                    true
                }
                None => false,
            }
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
                    destination: Destination::Command,
                    sites: vec![],
                    folder: None,
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
                    destination: Destination::Website,
                    sites: vec!["github.com".into(), "*.github.com".into()],
                    folder: None,
                })
                .unwrap();
        }
        let ui = Arc::new(FakeUi::default());
        let broker = Broker::new(vault, ui.clone(), Rules::default());
        Fixture { broker, ui, biometric_ok, biometric_checks, _dir: dir }
    }

    /// A vault with the AWS sign-in `mawaqit`: `production-ro` at level 1,
    /// `development-admin` at 3, `production-admin` at 4. `access_lifetime`
    /// is how long AWS's access tokens last.
    fn aws_fixture(access_lifetime: u64) -> (Fixture, Arc<FakeAws>) {
        let f = fixture();
        let api = Arc::new(FakeAws::default());
        *api.access_lifetime.lock().unwrap() = access_lifetime;
        let sign_in = aws::SignIn::start(api.as_ref(), "https://mawaqit.awsapps.com/start", "eu-west-3").unwrap();
        let session = sign_in.wait(api.as_ref(), &std::sync::atomic::AtomicBool::new(false)).unwrap();
        let profiles = aws::suggest_profiles(&session.accounts(api.as_ref()).unwrap());
        let aws = AwsSignIn { start_url: session.start_url.clone(), region: session.region.clone(), profiles };
        let Fixture { broker, ui, biometric_ok, biometric_checks, _dir } = f;
        let vault = broker.vault;
        vault.put_aws("mawaqit", aws, session.values(), None).unwrap();
        let broker = Broker::with_aws(vault, ui.clone(), Rules::default(), api.clone());
        (Fixture { broker, ui, biometric_ok, biometric_checks, _dir }, api)
    }

    fn aws_request(profile: &str, command: &str, session: &str) -> RunRequest {
        RunRequest {
            bindings: [("AWS_ACCESS_KEY_ID", "access_key_id"), ("AWS_SECRET_ACCESS_KEY", "secret_access_key")]
                .iter()
                .map(|(env, field)| Binding { env: env.to_string(), item: "mawaqit".into(), field: format!("{profile}/{field}") })
                .collect(),
            argv: command.split(' ').map(String::from).collect(),
            reason: "testing".into(),
            session: session.into(),
            ..Default::default()
        }
    }

    /// Keys whose fingerprint check stays up until it is cancelled, as a
    /// real dialog does while nobody touches the sensor.
    struct WaitingKeys {
        inner: SoftwareKeys,
        showing: Arc<AtomicBool>,
        cancelled: Arc<(Mutex<bool>, std::sync::Condvar)>,
    }

    impl crate::hardware::HardwareKeys for WaitingKeys {
        fn device_public(&self) -> Vec<u8> {
            self.inner.device_public()
        }
        fn biometric_public(&self) -> Vec<u8> {
            self.inner.biometric_public()
        }
        fn device_ecdh(&self, peer: &[u8]) -> crate::Result<crate::crypto::Key> {
            self.inner.device_ecdh(peer)
        }
        fn biometric_ecdh(&self, _peers: &[&[u8]], _prompt: &str) -> crate::Result<Vec<crate::crypto::Key>> {
            self.showing.store(true, Ordering::SeqCst);
            let (done, wake) = &*self.cancelled;
            let mut cancelled = lock(done);
            while !*cancelled {
                cancelled = wake.wait(cancelled).unwrap();
            }
            Err(Error::BiometricDenied)
        }
        fn cancel_biometric(&self) {
            let (done, wake) = &*self.cancelled;
            *lock(done) = true;
            wake.notify_all();
        }
    }

    #[test]
    fn answering_elsewhere_takes_the_fingerprint_dialog_down() {
        let dir = tempfile::tempdir().unwrap();
        let showing = Arc::new(AtomicBool::new(false));
        let keys = WaitingKeys {
            inner: SoftwareKeys::generate(|_| true),
            showing: showing.clone(),
            cancelled: Arc::new((Mutex::new(false), std::sync::Condvar::new())),
        };
        let vault = Vault::create(&dir.path().join("v.db"), Arc::new(keys), "test").unwrap();
        vault
            .put(NewItem {
                name: "L4".into(),
                level: Level::Biometric,
                values: [("value".to_string(), Zeroizing::new("four".to_string()))].into_iter().collect(),
                allow: vec![],
                max_grant_secs: 600,
                destination: Destination::Command,
                sites: vec![],
                folder: None,
            })
            .unwrap();
        let broker = Arc::new(Broker::new(vault, Arc::new(FakeUi::default()), Rules::default()));
        let run_id = broker.reserve_run();
        let asking = {
            let broker = broker.clone();
            std::thread::spawn(move || broker.run_reserved(run_id, &request(&["L4"], "deploy", "s"), &local()))
        };
        while !showing.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        broker.withdraw(run_id);
        assert_eq!(denied(asking.join().unwrap()), WITHDRAWN);
        assert_eq!(broker.vault().audit_tail(1).unwrap()[0].outcome, "withdrawn");
    }

    #[test]
    fn aws_profiles_have_their_own_levels() {
        let (f, _api) = aws_fixture(3600);
        let checks = || f.biometric_checks.load(Ordering::SeqCst);
        let before = checks();

        // Read-only: silent, logged under the profile's name.
        let env = released(f.broker.run(&aws_request("production-ro", "aws s3 ls", "s"), &local()));
        assert!(env["AWS_ACCESS_KEY_ID"].contains("136728947610ro"));
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 0);
        assert_eq!(f.broker.vault().audit_tail(1).unwrap()[0].secrets[0].name, "mawaqit/production-ro");

        // Level 3: asked; an approval for the session covers the same command.
        assert_eq!(denied(f.broker.run(&aws_request("development-admin", "aws s3 rm x", "s"), &local())), "denied by the user");
        *lock(&f.ui.answer) = Some(GrantScope::SessionAny);
        released(f.broker.run(&aws_request("development-admin", "aws s3 rm x", "s"), &local()));
        released(f.broker.run(&aws_request("development-admin", "aws s3 rm y", "s"), &local()));
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 2);

        // Level 4: the fingerprint, whatever was approved for other profiles.
        assert_eq!(checks(), before);
        let env = released(f.broker.run(&aws_request("production-admin", "aws s3 rm x", "s"), &local()));
        assert!(env["AWS_ACCESS_KEY_ID"].contains("136728947610admin"));
        assert_eq!(checks(), before + 1);
        released(f.broker.run(&aws_request("production-admin", "aws s3 rm x", "s"), &local()));
        assert_eq!(checks(), before + 1, "the same command again within minutes");
        f.biometric_ok.store(false, Ordering::SeqCst);
        assert_eq!(
            denied(f.broker.run(&aws_request("production-admin", "aws s3 rm z", "s"), &local())),
            "biometric check failed or was cancelled"
        );

        // A profile the sign-in does not offer, or two at once, are refused.
        assert!(denied(f.broker.run(&aws_request("staging-admin", "aws s3 ls", "s"), &local())).contains("no profile"));
        let mut two = aws_request("production-ro", "aws s3 ls", "s");
        two.bindings[1].field = "production-admin/secret_access_key".into();
        assert!(denied(f.broker.run(&two, &local())).contains("one profile"));
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 2, "refused before anyone is asked");
    }

    #[test]
    fn an_ended_aws_session_is_signed_in_again_while_the_request_waits() {
        let (f, api) = aws_fixture(0);
        api.session_alive.store(false, Ordering::SeqCst);
        let reason = denied(f.broker.run(&aws_request("production-ro", "aws s3 ls", "s"), &local()));
        assert!(reason.contains("Sign in again in Mayi"), "{reason}");
        assert_eq!(f.ui.sign_ins.load(Ordering::SeqCst), 1);

        *lock(&f.ui.revive) = Some(api.clone());
        released(f.broker.run(&aws_request("production-ro", "aws s3 ls", "s"), &local()));
        assert_eq!(f.ui.sign_ins.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_replaced_aws_refresh_token_is_kept_in_the_vault() {
        let (f, api) = aws_fixture(0);
        api.rotate.store(true, Ordering::SeqCst);
        let before = f.broker.vault().meta("mawaqit").unwrap();
        let stored = |m: &ItemMeta| f.broker.vault().reveal(&[m], "").unwrap().remove(0);
        let old = stored(&before);
        released(f.broker.run(&aws_request("production-ro", "aws s3 ls", "s"), &local()));
        let after = f.broker.vault().meta("mawaqit").unwrap();
        assert!(after.version > before.version);
        assert_ne!(stored(&after)["refresh_token"], old["refresh_token"]);
        assert_eq!(after.aws, before.aws, "profiles untouched");
    }

    #[test]
    fn a_level_1_profile_used_remotely_notifies_once_per_session() {
        let (f, _api) = aws_fixture(3600);
        let vm = Requester { id: "build-mac".into(), remote: true };
        for _ in 0..3 {
            released(f.broker.run(&aws_request("production-ro", "aws s3 ls", "claude-1"), &vm));
        }
        assert_eq!(f.ui.notices.load(Ordering::SeqCst), 1);
        released(f.broker.run(&aws_request("production-ro", "aws s3 ls", "claude-2"), &vm));
        assert_eq!(f.ui.notices.load(Ordering::SeqCst), 2);
        // A secret the owner set to level 2 still notifies at every use.
        released(f.broker.run(&request(&["L2"], "x", "claude-1"), &vm));
        released(f.broker.run(&request(&["L2"], "x", "claude-1"), &vm));
        assert_eq!(f.ui.notices.load(Ordering::SeqCst), 4);
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
    fn a_secret_from_a_newer_version_is_refused_before_anyone_is_asked() {
        let f = fixture();
        *lock(&f.ui.answer) = Some(GrantScope::Once);
        let mut meta = f.broker.vault().meta("L3").unwrap();
        meta.source = Source::Other("gcloud".into());
        f.broker.vault().write_meta(meta).unwrap();

        let reason = denied(f.broker.run(&request(&["L1", "L3"], "aws s3 ls", "s"), &local()));
        assert!(reason.starts_with("L3: ") && reason.contains("newer version of Mayi"), "{reason}");
        assert_eq!(f.ui.prompts.load(Ordering::SeqCst), 0);
        assert!(f.broker.list().unwrap().iter().any(|s| s.name == "L3"), "still listed");
        released(f.broker.run(&request(&["L1"], "aws s3 ls", "s"), &local()));
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
        assert_eq!(denied(f.broker.run_reserved(run_id, &request(&["L3"], "x", "s"), &local())), WITHDRAWN);
        let log = f.broker.vault().audit_tail(1).unwrap();
        assert_eq!(log[0].outcome, "withdrawn");
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

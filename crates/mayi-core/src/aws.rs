//! AWS IAM Identity Center (SSO), from the vault device.
//!
//! The vault device signs in with AWS's device authorization flow: the owner
//! approves in a browser, through AWS's own sign-in (their identity
//! provider, password, two-factor). The device keeps that session and
//! refreshes it silently, as the AWS CLI does, until AWS ends it (8 hours by
//! default). A request names one of the sign-in's profiles; what is released
//! is that one role's temporary credentials. The session itself never
//! leaves the device: whoever holds it could fetch any role.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::model::{AwsProfile, ItemMeta, Level, SecretValues};
use crate::provider::{Provider, Refusal, Release, Released};

// What is stored, encrypted, as the sign-in's values.
const START_URL: &str = "start_url";
const REGION: &str = "region";
const CLIENT_ID: &str = "client_id";
const CLIENT_SECRET: &str = "client_secret";
const CLIENT_EXPIRES: &str = "client_expires_at";
const ACCESS_TOKEN: &str = "access_token";
const ACCESS_EXPIRES: &str = "access_expires_at";
const REFRESH_TOKEN: &str = "refresh_token";

/// What a request may ask for, as `PROFILE/FIELD`.
pub const FIELD_ACCESS_KEY_ID: &str = "access_key_id";
pub const FIELD_SECRET_ACCESS_KEY: &str = "secret_access_key";
pub const FIELD_SESSION_TOKEN: &str = "session_token";
/// When the credentials expire, RFC 3339 in UTC, for `credential_process`.
pub const FIELD_EXPIRATION: &str = "expiration";
pub const FIELDS: [&str; 4] = [FIELD_ACCESS_KEY_ID, FIELD_SECRET_ACCESS_KEY, FIELD_SESSION_TOKEN, FIELD_EXPIRATION];

/// The name AWS shows on its approval page: the owner checks it says Mayi.
pub const CLIENT_NAME: &str = "Mayi";

/// Credentials closer than this to expiring are fetched again.
const CREDENTIALS_MARGIN_SECS: u64 = 300;
/// An access token closer than this to expiring is refreshed first.
const TOKEN_MARGIN_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwsError {
    /// The owner has not answered in the browser yet.
    Pending,
    /// Polled too often: wait longer.
    SlowDown,
    /// The session or the app's registration ended or was refused: the
    /// owner must sign in again.
    SignInNeeded(String),
    Failed(String),
}

impl std::fmt::Display for AwsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AwsError::Pending => f.write_str("waiting for approval in the browser"),
            AwsError::SlowDown => f.write_str("asked AWS too often"),
            AwsError::SignInNeeded(why) | AwsError::Failed(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for AwsError {}

/// This app's registration with AWS's sign-in service.
#[derive(Clone)]
pub struct Client {
    pub id: String,
    pub secret: Zeroizing<String>,
    /// Unix seconds; a new registration, and so a new sign-in, after that.
    pub expires_at: u64,
}

pub struct DeviceAuth {
    pub device_code: Zeroizing<String>,
    pub user_code: String,
    /// The approval page with the code filled in.
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

pub struct Token {
    pub access_token: Zeroizing<String>,
    pub expires_in: u64,
    pub refresh_token: Option<Zeroizing<String>>,
}

pub enum Grant<'a> {
    DeviceCode(&'a str),
    Refresh(&'a str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub id: String,
    pub name: String,
    pub roles: Vec<String>,
}

#[derive(Clone)]
pub struct RoleCredentials {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Zeroizing<String>,
    /// Unix seconds.
    pub expires_at: u64,
}

/// AWS's sign-in (OIDC) and portal services. [`HttpApi`] talks to AWS;
/// tests stand in for it.
pub trait Api: Send + Sync {
    fn register_client(&self, region: &str) -> Result<Client, AwsError>;
    fn start_device_authorization(&self, region: &str, client: &Client, start_url: &str)
        -> Result<DeviceAuth, AwsError>;
    fn create_token(&self, region: &str, client: &Client, grant: Grant) -> Result<Token, AwsError>;
    /// Account ids and names.
    fn list_accounts(&self, region: &str, access_token: &str) -> Result<Vec<(String, String)>, AwsError>;
    fn list_account_roles(&self, region: &str, access_token: &str, account_id: &str) -> Result<Vec<String>, AwsError>;
    fn get_role_credentials(&self, region: &str, access_token: &str, account_id: &str, role: &str)
        -> Result<RoleCredentials, AwsError>;
}

pub(crate) fn now_secs() -> u64 {
    crate::now_ms() / 1000
}

/// A region as AWS names them (`eu-west-3`), so it can go into a host name.
pub fn check_region(region: &str) -> Result<(), String> {
    let parts: Vec<&str> = region.split('-').collect();
    let ok = parts.len() >= 3
        && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()))
        && parts.last().is_some_and(|p| p.chars().all(|c| c.is_ascii_digit()));
    if ok {
        Ok(())
    } else {
        Err(format!("{region:?} is not an AWS region, such as eu-west-1"))
    }
}

/// The portal's start URL as AWS knows it: https, without the `#/` the
/// browser adds or a trailing slash.
pub fn normalize_start_url(url: &str) -> Result<String, String> {
    let url = url.trim();
    let url = url.split('#').next().unwrap_or(url).trim_end_matches('/');
    let host = url.strip_prefix("https://").map(|rest| rest.split('/').next().unwrap_or(""));
    match host {
        Some(host) if !host.is_empty() && !host.contains(char::is_whitespace) => Ok(url.to_string()),
        _ => Err(format!("{url:?} is not a start URL, such as https://example.awsapps.com/start")),
    }
}

/// Profile names go into requests (`SIGNIN/PROFILE`) and AWS CLI profile
/// names, so they keep to letters, digits, `.`, `_` and `-`.
pub fn check_profiles(profiles: &[AwsProfile]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for p in profiles {
        let valid = !p.name.is_empty() && p.name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !valid {
            return Err(format!("profile name {:?}: use letters, digits, '.', '_' and '-'", p.name));
        }
        if !seen.insert(p.name.as_str()) {
            return Err(format!("two profiles are called {:?}", p.name));
        }
        if p.account_id.len() != 12 || !p.account_id.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("profile {}: {:?} is not an AWS account id", p.name, p.account_id));
        }
        if p.role.trim().is_empty() {
            return Err(format!("profile {} has no role", p.name));
        }
    }
    Ok(())
}

fn slug(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    out.trim_end_matches('-').to_string()
}

/// Whether a role looks read-only by its name (`ro`, `ReadOnlyAccess`,
/// `ViewOnly`, `SecurityAudit`).
fn read_only(role: &str) -> bool {
    let lower = role.to_ascii_lowercase();
    let words: Vec<String> = lower.split(|c: char| !c.is_ascii_alphanumeric()).map(String::from).collect();
    words.iter().any(|w| w == "ro" || w == "read" || w == "view")
        || ["readonly", "viewonly", "audit", "viewer", "reader"].iter().any(|k| lower.contains(k))
}

fn production(account: &str) -> bool {
    let lower = account.to_ascii_lowercase();
    lower.split(|c: char| !c.is_ascii_alphanumeric()).any(|w| matches!(w, "prod" | "production" | "prd" | "live"))
}

/// A profile for every role, named like AWS CLI profiles
/// (`production-admin`), with a suggested level: read-only roles 1, roles
/// that can change production 4, the others 3. The owner changes any.
pub fn suggest_profiles(accounts: &[Account]) -> Vec<AwsProfile> {
    let mut profiles: Vec<AwsProfile> = Vec::new();
    for account in accounts {
        for role in &account.roles {
            let base = match (slug(&account.name), slug(role)) {
                (a, r) if a.is_empty() => format!("{}-{r}", account.id),
                (a, r) => format!("{a}-{r}"),
            };
            let name = if profiles.iter().any(|p| p.name == base) { format!("{base}-{}", account.id) } else { base };
            let level = if read_only(role) {
                Level::Log
            } else if production(&account.name) {
                Level::Biometric
            } else {
                Level::Approve
            };
            profiles.push(AwsProfile {
                name,
                account_id: account.id.clone(),
                account_name: account.name.clone(),
                role: role.clone(),
                level,
            });
        }
    }
    profiles
}

/// A sign-in under way: the owner approves it in a browser.
pub struct SignIn {
    pub start_url: String,
    pub region: String,
    client: Client,
    auth: DeviceAuth,
    started: Instant,
}

impl SignIn {
    pub fn start(api: &dyn Api, start_url: &str, region: &str) -> Result<Self, AwsError> {
        let start_url = normalize_start_url(start_url).map_err(AwsError::Failed)?;
        check_region(region).map_err(AwsError::Failed)?;
        let client = api.register_client(region)?;
        let auth = api.start_device_authorization(region, &client, &start_url)?;
        Ok(Self { start_url, region: region.to_string(), client, auth, started: Instant::now() })
    }

    /// The code AWS's page shows, for the owner to compare.
    pub fn user_code(&self) -> &str {
        &self.auth.user_code
    }

    /// The approval page, with the code filled in.
    pub fn verification_url(&self) -> &str {
        &self.auth.verification_uri_complete
    }

    /// Waits until the owner approves in the browser, the code expires, or
    /// `cancelled` is set.
    pub fn wait(&self, api: &dyn Api, cancelled: &AtomicBool) -> Result<Session, AwsError> {
        let mut interval = Duration::from_secs(self.auth.interval);
        let deadline = self.started + Duration::from_secs(self.auth.expires_in);
        loop {
            let until = Instant::now() + interval;
            while Instant::now() < until {
                if cancelled.load(Ordering::SeqCst) {
                    return Err(AwsError::Failed("the sign-in was cancelled".into()));
                }
                std::thread::sleep(Duration::from_millis(100).min(until - Instant::now()));
            }
            if cancelled.load(Ordering::SeqCst) {
                return Err(AwsError::Failed("the sign-in was cancelled".into()));
            }
            if Instant::now() > deadline {
                return Err(AwsError::Failed("the sign-in expired before it was approved: start again".into()));
            }
            match api.create_token(&self.region, &self.client, Grant::DeviceCode(&self.auth.device_code)) {
                Ok(token) => {
                    return Ok(Session {
                        start_url: self.start_url.clone(),
                        region: self.region.clone(),
                        client: self.client.clone(),
                        access_expires_at: now_secs() + token.expires_in,
                        access_token: token.access_token,
                        refresh_token: token.refresh_token,
                    })
                }
                Err(AwsError::Pending) => {}
                Err(AwsError::SlowDown) => interval += Duration::from_secs(5),
                Err(AwsError::SignInNeeded(_)) => {
                    return Err(AwsError::Failed("the sign-in was refused or expired in the browser".into()))
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// A signed-in session: what an AWS sign-in stores.
pub struct Session {
    pub start_url: String,
    pub region: String,
    client: Client,
    access_token: Zeroizing<String>,
    access_expires_at: u64,
    refresh_token: Option<Zeroizing<String>>,
}

impl Session {
    /// Every account the session can reach, with its roles, sorted by name.
    pub fn accounts(&self, api: &dyn Api) -> Result<Vec<Account>, AwsError> {
        accounts(api, &self.region, &self.access_token)
    }

    pub fn values(&self) -> SecretValues {
        let mut v = SecretValues::new();
        let mut put = |k: &str, value: &str| {
            v.insert(k.to_string(), Zeroizing::new(value.to_string()));
        };
        put(START_URL, &self.start_url);
        put(REGION, &self.region);
        put(CLIENT_ID, &self.client.id);
        put(CLIENT_SECRET, &self.client.secret);
        put(CLIENT_EXPIRES, &self.client.expires_at.to_string());
        put(ACCESS_TOKEN, &self.access_token);
        put(ACCESS_EXPIRES, &self.access_expires_at.to_string());
        if let Some(refresh) = &self.refresh_token {
            put(REFRESH_TOKEN, refresh);
        }
        v
    }

    pub fn from_values(values: &SecretValues) -> Result<Self, String> {
        let get = |k: &str| values.get(k).map(|v| v.to_string()).ok_or_else(|| format!("the sign-in has no {k}"));
        let number = |k: &str| get(k)?.parse::<u64>().map_err(|_| format!("the sign-in's {k} is not a number"));
        Ok(Self {
            start_url: get(START_URL)?,
            region: get(REGION)?,
            client: Client {
                id: get(CLIENT_ID)?,
                secret: Zeroizing::new(get(CLIENT_SECRET)?),
                expires_at: number(CLIENT_EXPIRES)?,
            },
            access_token: Zeroizing::new(get(ACCESS_TOKEN)?),
            access_expires_at: number(ACCESS_EXPIRES)?,
            refresh_token: values.get(REFRESH_TOKEN).cloned(),
        })
    }
}

fn accounts(api: &dyn Api, region: &str, access_token: &str) -> Result<Vec<Account>, AwsError> {
    let mut out = Vec::new();
    for (id, name) in api.list_accounts(region, access_token)? {
        let mut roles = api.list_account_roles(region, access_token, &id)?;
        roles.sort();
        out.push(Account { id, name, roles });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    Ok(out)
}

/// `PROFILE/FIELD`, as an AWS sign-in's bindings name what they want.
pub fn split_field(field: &str) -> Result<(&str, &str), String> {
    match field.split_once('/') {
        Some((profile, f)) if !profile.is_empty() && FIELDS.contains(&f) => Ok((profile, f)),
        _ => Err(format!("{field:?}: an AWS sign-in gives PROFILE/{}", FIELDS.join(", PROFILE/"))),
    }
}

/// The profile a request uses: every binding of one sign-in must name the
/// same one.
pub fn requested_profile<'a>(meta: &'a ItemMeta, fields: &[&str]) -> Result<&'a AwsProfile, String> {
    let aws = meta.aws.as_ref().ok_or_else(|| format!("{} has no AWS portal", meta.name))?;
    let mut name: Option<&str> = None;
    for field in fields {
        let (profile, _) = split_field(field)?;
        match name {
            Some(n) if n != profile => return Err(format!("one request uses one profile of {}", meta.name)),
            _ => name = Some(profile),
        }
    }
    let name = name.ok_or_else(|| format!("no profile of {} requested", meta.name))?;
    aws.profiles.iter().find(|p| p.name == name).ok_or_else(|| {
        let known: Vec<&str> = aws.profiles.iter().map(|p| p.name.as_str()).collect();
        format!("{} has no profile {name:?} (it has: {})", meta.name, known.join(", "))
    })
}

/// RFC 3339 in UTC, as `credential_process` wants an expiry.
fn rfc3339(unix_secs: u64) -> String {
    let (h, m, s) = ((unix_secs / 3600) % 24, (unix_secs / 60) % 60, unix_secs % 60);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = (unix_secs / 86400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

#[derive(Default)]
struct ItemState {
    /// A token refreshed here, newer than the stored one.
    access: Option<(Zeroizing<String>, u64)>,
    refresh: Option<Zeroizing<String>>,
    /// Credentials by account and role, until they near their expiry.
    roles: HashMap<(String, String), RoleCredentials>,
}

/// Releases AWS sign-ins. Keeps refreshed tokens and fetched credentials in
/// memory, so read-only profiles answer at once; persists a token only when
/// AWS replaces the refresh token.
pub struct AwsProvider {
    api: Arc<dyn Api>,
    state: Mutex<HashMap<String, ItemState>>,
}

fn refusal(e: AwsError) -> Refusal {
    match e {
        AwsError::SignInNeeded(why) => Refusal::SignInNeeded(why),
        other => Refusal::Failed(other.to_string()),
    }
}

impl AwsProvider {
    pub fn new(api: Arc<dyn Api>) -> Self {
        Self { api, state: Mutex::default() }
    }

    pub fn api(&self) -> &dyn Api {
        self.api.as_ref()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, ItemState>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drops what is cached for a sign-in: after signing in again, or when
    /// it is removed.
    pub fn forget(&self, item_id: &str) {
        self.lock().remove(item_id);
    }

    /// A working access token, refreshing it if needed. Returns values to
    /// store when AWS replaced the refresh token.
    fn access_token(
        &self,
        item: &mut ItemState,
        stored: &SecretValues,
        now: u64,
    ) -> Result<(Zeroizing<String>, Option<SecretValues>), Refusal> {
        if let Some((token, expires)) = &item.access {
            if *expires > now + TOKEN_MARGIN_SECS {
                return Ok((token.clone(), None));
            }
        }
        let mut session = Session::from_values(stored).map_err(Refusal::Failed)?;
        if item.access.is_none() && session.access_expires_at > now + TOKEN_MARGIN_SECS {
            item.access = Some((session.access_token.clone(), session.access_expires_at));
            return Ok((session.access_token, None));
        }
        if session.client.expires_at <= now {
            return Err(Refusal::SignInNeeded("Mayi's registration with AWS ended".into()));
        }
        let refresh = item.refresh.clone().or(session.refresh_token.clone()).ok_or_else(|| {
            Refusal::SignInNeeded("the AWS session ended".into())
        })?;
        let token = self
            .api
            .create_token(&session.region, &session.client, Grant::Refresh(&refresh))
            .map_err(|e| match e {
                AwsError::SignInNeeded(_) => Refusal::SignInNeeded("the AWS session ended".into()),
                other => refusal(other),
            })?;
        let expires = now + token.expires_in;
        item.access = Some((token.access_token.clone(), expires));
        let store = token.refresh_token.filter(|new| **new != *refresh).map(|new| {
            item.refresh = Some(new.clone());
            session.refresh_token = Some(new);
            session.access_token = token.access_token.clone();
            session.access_expires_at = expires;
            session.values()
        });
        Ok((token.access_token, store))
    }

    /// The accounts and roles the stored session reaches, to add profiles
    /// later without signing in again.
    pub fn accounts(&self, meta: &ItemMeta, stored: &SecretValues) -> Result<(Vec<Account>, Option<SecretValues>), Refusal> {
        let region = &meta.aws.as_ref().ok_or_else(|| Refusal::Failed("not an AWS sign-in".into()))?.region;
        let mut state = self.lock();
        let item = state.entry(meta.id.clone()).or_default();
        let (token, store) = self.access_token(item, stored, now_secs())?;
        let list = accounts(self.api.as_ref(), region, &token).map_err(refusal)?;
        Ok((list, store))
    }

    fn credentials(
        &self,
        meta: &ItemMeta,
        profile: &AwsProfile,
        stored: &SecretValues,
        now: u64,
    ) -> Result<(RoleCredentials, Option<SecretValues>), Refusal> {
        let region = &meta.aws.as_ref().ok_or_else(|| Refusal::Failed("not an AWS sign-in".into()))?.region;
        let mut state = self.lock();
        let item = state.entry(meta.id.clone()).or_default();
        let key = (profile.account_id.clone(), profile.role.clone());
        if let Some(c) = item.roles.get(&key).filter(|c| c.expires_at > now + CREDENTIALS_MARGIN_SECS) {
            return Ok((c.clone(), None));
        }
        let (token, mut store) = self.access_token(item, stored, now)?;
        let fetched = match self.api.get_role_credentials(region, &token, &profile.account_id, &profile.role) {
            // Ended before its time (signed out elsewhere): refresh once.
            Err(AwsError::SignInNeeded(_)) => {
                // Marked expired, so the stored token is not tried again.
                item.access = Some((Zeroizing::new(String::new()), 0));
                let (token, again) = self.access_token(item, stored, now)?;
                store = again.or(store);
                self.api.get_role_credentials(region, &token, &profile.account_id, &profile.role)
            }
            other => other,
        }
        .map_err(refusal)?;
        item.roles.insert(key, fetched.clone());
        Ok((fetched, store))
    }
}

impl Provider for AwsProvider {
    fn check(&self, values: &mut SecretValues) -> Result<(), String> {
        Session::from_values(values).map(|_| ())
    }

    fn release(&self, r: &Release) -> Result<Released, Refusal> {
        let profile = requested_profile(r.meta, r.fields).map_err(Refusal::Failed)?;
        let (creds, store) = self.credentials(r.meta, profile, r.stored, r.now_secs)?;
        let mut values = SecretValues::new();
        for field in r.fields {
            let (_, f) = split_field(field).map_err(Refusal::Failed)?;
            let value = match f {
                FIELD_ACCESS_KEY_ID => Zeroizing::new(creds.access_key_id.clone()),
                FIELD_SECRET_ACCESS_KEY => creds.secret_access_key.clone(),
                FIELD_SESSION_TOKEN => creds.session_token.clone(),
                _ => Zeroizing::new(rfc3339(creds.expires_at)),
            };
            values.insert(field.to_string(), value);
        }
        Ok(Released { values, store })
    }
}

/// Talks to AWS over HTTPS.
pub struct HttpApi {
    agent: ureq::Agent,
}

impl Default for HttpApi {
    fn default() -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .user_agent(concat!("mayi/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self { agent }
    }
}

/// Percent-encodes a query parameter.
fn encode(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn text(value: &Value, key: &str) -> Result<String, AwsError> {
    value[key].as_str().map(String::from).ok_or_else(|| AwsError::Failed(format!("AWS's answer has no {key}")))
}

fn number(value: &Value, key: &str) -> Result<u64, AwsError> {
    value[key].as_u64().ok_or_else(|| AwsError::Failed(format!("AWS's answer has no {key}")))
}

/// Sorts an error answer: OIDC errors name themselves in `error`, the
/// portal's in a header or `__type`.
fn classify(status: u16, kind: &str, body: &Value) -> AwsError {
    let error = body["error"].as_str().or(body["__type"].as_str()).unwrap_or(kind);
    let error = error.rsplit('#').next().unwrap_or(error).split(':').next().unwrap_or(error);
    let message = body["error_description"].as_str().or(body["message"].as_str()).or(body["Message"].as_str());
    match error {
        "authorization_pending" | "AuthorizationPendingException" => AwsError::Pending,
        "slow_down" | "SlowDownException" => AwsError::SlowDown,
        "expired_token" | "ExpiredTokenException" | "invalid_grant" | "InvalidGrantException" | "access_denied"
        | "AccessDeniedException" | "invalid_client" | "InvalidClientException" | "unauthorized_client"
        | "UnauthorizedClientException" | "UnauthorizedException" => {
            AwsError::SignInNeeded(message.unwrap_or("AWS no longer accepts the session").to_string())
        }
        _ if status == 401 => AwsError::SignInNeeded("AWS no longer accepts the session".into()),
        _ => AwsError::Failed(format!("AWS answered {status}: {}", message.unwrap_or(error))),
    }
}

impl HttpApi {
    fn answer(response: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Value, AwsError> {
        let mut response = response.map_err(|e| AwsError::Failed(format!("could not reach AWS: {e}")))?;
        let status = response.status().as_u16();
        let kind = response
            .headers()
            .get("x-amzn-errortype")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = response.body_mut().read_to_string().map_err(|e| AwsError::Failed(format!("AWS's answer: {e}")))?;
        let value: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        if (200..300).contains(&status) {
            Ok(value)
        } else {
            Err(classify(status, &kind, &value))
        }
    }

    fn oidc(&self, region: &str, path: &str, body: Value) -> Result<Value, AwsError> {
        check_region(region).map_err(AwsError::Failed)?;
        let url = format!("https://oidc.{region}.amazonaws.com{path}");
        Self::answer(self.agent.post(&url).header("content-type", "application/json").send(body.to_string()))
    }

    fn portal(&self, region: &str, path: &str, token: &str) -> Result<Value, AwsError> {
        check_region(region).map_err(AwsError::Failed)?;
        let url = format!("https://portal.sso.{region}.amazonaws.com{path}");
        Self::answer(self.agent.get(&url).header("x-amz-sso_bearer_token", token).call())
    }
}

impl Api for HttpApi {
    fn register_client(&self, region: &str) -> Result<Client, AwsError> {
        let v = self.oidc(
            region,
            "/client/register",
            json!({
                "clientName": CLIENT_NAME,
                "clientType": "public",
                "scopes": ["sso:account:access"],
                "grantTypes": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
            }),
        )?;
        Ok(Client {
            id: text(&v, "clientId")?,
            secret: Zeroizing::new(text(&v, "clientSecret")?),
            expires_at: number(&v, "clientSecretExpiresAt")?,
        })
    }

    fn start_device_authorization(&self, region: &str, client: &Client, start_url: &str) -> Result<DeviceAuth, AwsError> {
        let v = self.oidc(
            region,
            "/device_authorization",
            json!({ "clientId": client.id, "clientSecret": *client.secret, "startUrl": start_url }),
        )?;
        Ok(DeviceAuth {
            device_code: Zeroizing::new(text(&v, "deviceCode")?),
            user_code: text(&v, "userCode")?,
            verification_uri_complete: text(&v, "verificationUriComplete")?,
            expires_in: number(&v, "expiresIn")?,
            interval: v["interval"].as_u64().unwrap_or(5),
        })
    }

    fn create_token(&self, region: &str, client: &Client, grant: Grant) -> Result<Token, AwsError> {
        let mut body = json!({ "clientId": client.id, "clientSecret": *client.secret });
        match grant {
            Grant::DeviceCode(code) => {
                body["grantType"] = "urn:ietf:params:oauth:grant-type:device_code".into();
                body["deviceCode"] = code.into();
            }
            Grant::Refresh(token) => {
                body["grantType"] = "refresh_token".into();
                body["refreshToken"] = token.into();
            }
        }
        let v = self.oidc(region, "/token", body)?;
        Ok(Token {
            access_token: Zeroizing::new(text(&v, "accessToken")?),
            expires_in: number(&v, "expiresIn")?,
            refresh_token: v["refreshToken"].as_str().map(|t| Zeroizing::new(t.to_string())),
        })
    }

    fn list_accounts(&self, region: &str, access_token: &str) -> Result<Vec<(String, String)>, AwsError> {
        let mut out = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let mut path = "/assignment/accounts?max_result=100".to_string();
            if let Some(n) = &next {
                path.push_str(&format!("&next_token={}", encode(n)));
            }
            let v = self.portal(region, &path, access_token)?;
            for a in v["accountList"].as_array().into_iter().flatten() {
                out.push((text(a, "accountId")?, a["accountName"].as_str().unwrap_or("").to_string()));
            }
            next = v["nextToken"].as_str().map(String::from);
            if next.is_none() {
                return Ok(out);
            }
        }
    }

    fn list_account_roles(&self, region: &str, access_token: &str, account_id: &str) -> Result<Vec<String>, AwsError> {
        let mut out = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let mut path = format!("/assignment/roles?account_id={}&max_result=100", encode(account_id));
            if let Some(n) = &next {
                path.push_str(&format!("&next_token={}", encode(n)));
            }
            let v = self.portal(region, &path, access_token)?;
            for r in v["roleList"].as_array().into_iter().flatten() {
                out.push(text(r, "roleName")?);
            }
            next = v["nextToken"].as_str().map(String::from);
            if next.is_none() {
                return Ok(out);
            }
        }
    }

    fn get_role_credentials(&self, region: &str, access_token: &str, account_id: &str, role: &str) -> Result<RoleCredentials, AwsError> {
        let path = format!("/federation/credentials?account_id={}&role_name={}", encode(account_id), encode(role));
        let v = self.portal(region, &path, access_token)?;
        let c = &v["roleCredentials"];
        Ok(RoleCredentials {
            access_key_id: text(c, "accessKeyId")?,
            secret_access_key: Zeroizing::new(text(c, "secretAccessKey")?),
            session_token: Zeroizing::new(text(c, "sessionToken")?),
            expires_at: number(c, "expiration")? / 1000,
        })
    }
}

/// A stand-in for AWS, for tests here and in other crates.
pub mod fake {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Accounts `development` and `production`, a session that refreshes
    /// with a rotating refresh token, and credentials that say which role
    /// and which token fetched them.
    pub struct FakeAws {
        pub token_calls: AtomicUsize,
        pub credential_calls: AtomicUsize,
        /// Refresh tokens AWS still accepts.
        pub valid_refresh: Mutex<Vec<String>>,
        /// When false, refreshing fails as if the AWS session ended.
        pub session_alive: AtomicBool,
        /// Lifetime of access tokens it hands out.
        pub access_lifetime: Mutex<u64>,
        /// When true, AWS hands out a new refresh token on each refresh.
        pub rotate: AtomicBool,
    }

    impl Default for FakeAws {
        fn default() -> Self {
            Self {
                token_calls: AtomicUsize::new(0),
                credential_calls: AtomicUsize::new(0),
                valid_refresh: Mutex::new(vec![]),
                session_alive: AtomicBool::new(true),
                access_lifetime: Mutex::new(3600),
                rotate: AtomicBool::new(false),
            }
        }
    }

    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    impl FakeAws {
        fn issue(&self, n: usize) -> Token {
            let refresh = format!("refresh-{n}");
            lock(&self.valid_refresh).push(refresh.clone());
            Token {
                access_token: Zeroizing::new(format!("access-{n}")),
                expires_in: *lock(&self.access_lifetime),
                refresh_token: Some(Zeroizing::new(refresh)),
            }
        }
    }

    impl Api for FakeAws {
        fn register_client(&self, _region: &str) -> Result<Client, AwsError> {
            Ok(Client { id: "client".into(), secret: Zeroizing::new("client-secret".into()), expires_at: now_secs() + 86_400 * 90 })
        }

        fn start_device_authorization(&self, _region: &str, _c: &Client, start_url: &str) -> Result<DeviceAuth, AwsError> {
            Ok(DeviceAuth {
                device_code: Zeroizing::new("device".into()),
                user_code: "ABCD-EFGH".into(),
                verification_uri_complete: format!("{start_url}/verify?code=ABCD-EFGH"),
                expires_in: 600,
                interval: 0,
            })
        }

        fn create_token(&self, _region: &str, _c: &Client, grant: Grant) -> Result<Token, AwsError> {
            let n = self.token_calls.fetch_add(1, Ordering::SeqCst) + 1;
            match grant {
                Grant::DeviceCode(_) => Ok(self.issue(n)),
                Grant::Refresh(token) => {
                    if !self.session_alive.load(Ordering::SeqCst) || !lock(&self.valid_refresh).iter().any(|t| t == token) {
                        return Err(AwsError::SignInNeeded("invalid_grant".into()));
                    }
                    if self.rotate.load(Ordering::SeqCst) {
                        lock(&self.valid_refresh).retain(|t| t != token);
                        Ok(self.issue(n))
                    } else {
                        Ok(Token {
                            access_token: Zeroizing::new(format!("access-{n}")),
                            expires_in: *lock(&self.access_lifetime),
                            refresh_token: Some(Zeroizing::new(token.to_string())),
                        })
                    }
                }
            }
        }

        fn list_accounts(&self, _region: &str, _token: &str) -> Result<Vec<(String, String)>, AwsError> {
            Ok(vec![("136728947610".into(), "production".into()), ("275854128200".into(), "development".into())])
        }

        fn list_account_roles(&self, _region: &str, _token: &str, account_id: &str) -> Result<Vec<String>, AwsError> {
            Ok(match account_id {
                "136728947610" => vec!["admin".into(), "ro".into()],
                _ => vec!["admin".into()],
            })
        }

        fn get_role_credentials(&self, _region: &str, token: &str, account_id: &str, role: &str) -> Result<RoleCredentials, AwsError> {
            if token.is_empty() {
                return Err(AwsError::SignInNeeded("UnauthorizedException".into()));
            }
            let n = self.credential_calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(RoleCredentials {
                access_key_id: format!("ASIA{account_id}{role}{n}"),
                secret_access_key: Zeroizing::new(format!("secret-{role}-{n}")),
                session_token: Zeroizing::new(format!("session-{token}-{n}")),
                expires_at: now_secs() + 3600,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeAws;
    use super::*;
    use crate::model::{AwsSignIn, Destination, Source};

    fn signed_in(api: &FakeAws) -> Session {
        let sign_in = SignIn::start(api, "https://mawaqit.awsapps.com/start/#/", "eu-west-3").unwrap();
        assert_eq!(sign_in.start_url, "https://mawaqit.awsapps.com/start");
        assert_eq!(sign_in.user_code(), "ABCD-EFGH");
        sign_in.wait(api, &AtomicBool::new(false)).unwrap()
    }

    fn meta(profiles: Vec<AwsProfile>) -> ItemMeta {
        ItemMeta {
            id: "aws1".into(),
            name: "mawaqit".into(),
            level: Level::Log,
            allow: vec![],
            max_grant_secs: 600,
            fields: FIELDS.iter().map(|f| f.to_string()).collect(),
            destination: Destination::Command,
            source: Source::AwsSso,
            sites: vec![],
            folder: None,
            rotate: vec![],
            aws: Some(AwsSignIn { start_url: "https://mawaqit.awsapps.com/start".into(), region: "eu-west-3".into(), profiles }),
            unknown_fields: Default::default(),
            version: 1,
        }
    }

    #[test]
    fn regions_start_urls_and_profile_names_are_checked() {
        assert!(check_region("eu-west-3").is_ok());
        assert!(check_region("us-gov-west-1").is_ok());
        for bad in ["", "eu", "eu-west", "EU-WEST-1", "eu-west-1.evil.com", "eu-west-x"] {
            assert!(check_region(bad).is_err(), "{bad}");
        }
        assert_eq!(normalize_start_url(" https://d-123.awsapps.com/start/ ").unwrap(), "https://d-123.awsapps.com/start");
        assert!(normalize_start_url("http://x.awsapps.com/start").is_err());
        assert!(normalize_start_url("https:///start").is_err());

        let accounts = vec![Account { id: "136728947610".into(), name: "production".into(), roles: vec!["admin".into()] }];
        let mut profiles = suggest_profiles(&accounts);
        assert!(check_profiles(&profiles).is_ok());
        profiles[0].name = "prod/admin".into();
        assert!(check_profiles(&profiles).is_err());
    }

    #[test]
    fn suggested_profiles_follow_the_roles() {
        let accounts = vec![
            Account { id: "275854128200".into(), name: "development".into(), roles: vec!["admin".into()] },
            Account { id: "540883426206".into(), name: "preprod".into(), roles: vec!["admin".into()] },
            Account { id: "136728947610".into(), name: "production".into(), roles: vec!["admin".into(), "ro".into()] },
            Account { id: "111111111111".into(), name: "Prod EU".into(), roles: vec!["ReadOnlyAccess".into(), "PowerUserAccess".into()] },
        ];
        let got: Vec<(String, Level)> = suggest_profiles(&accounts).into_iter().map(|p| (p.name, p.level)).collect();
        assert_eq!(
            got,
            [
                ("development-admin".to_string(), Level::Approve),
                ("preprod-admin".into(), Level::Approve),
                ("production-admin".into(), Level::Biometric),
                ("production-ro".into(), Level::Log),
                ("prod-eu-readonlyaccess".into(), Level::Log),
                ("prod-eu-poweruseraccess".into(), Level::Biometric),
            ]
        );
    }

    #[test]
    fn a_session_round_trips_through_its_values_and_lists_accounts() {
        let api = FakeAws::default();
        let session = signed_in(&api);
        let again = Session::from_values(&session.values()).unwrap();
        assert_eq!(again.region, "eu-west-3");
        assert_eq!(*again.refresh_token.unwrap(), "refresh-1");
        let accounts = session.accounts(&api).unwrap();
        assert_eq!(accounts[0].name, "development");
        assert_eq!(accounts[1].roles, ["admin", "ro"]);
    }

    #[test]
    fn a_cancelled_sign_in_stops() {
        let api = FakeAws::default();
        let sign_in = SignIn::start(&api, "https://x.awsapps.com/start", "eu-west-1").unwrap();
        assert!(sign_in.wait(&api, &AtomicBool::new(true)).is_err());
    }

    fn release(p: &AwsProvider, meta: &ItemMeta, stored: &SecretValues, fields: &[&str], now: u64) -> Result<Released, Refusal> {
        p.release(&Release { meta, stored, fields, now_secs: now })
    }

    #[test]
    fn credentials_are_cached_per_role_and_refreshed_silently() {
        let api = Arc::new(FakeAws::default());
        let stored = signed_in(&api).values();
        let meta = meta(suggest_profiles(&signed_in(&api).accounts(api.as_ref()).unwrap()));
        let provider = AwsProvider::new(api.clone());
        let now = now_secs();

        let ro = release(&provider, &meta, &stored, &["production-ro/access_key_id", "production-ro/expiration"], now).unwrap();
        assert!(ro.values["production-ro/access_key_id"].contains("136728947610ro"));
        assert!(ro.values["production-ro/expiration"].ends_with('Z'));
        assert!(ro.store.is_none());
        release(&provider, &meta, &stored, &["production-ro/access_key_id"], now).unwrap();
        assert_eq!(api.credential_calls.load(Ordering::SeqCst), 1, "cached until near expiry");

        // Two hours later the access token is old: refreshed without asking.
        let tokens_before = api.token_calls.load(Ordering::SeqCst);
        let admin = release(&provider, &meta, &stored, &["production-admin/session_token"], now + 7200).unwrap();
        assert_eq!(api.token_calls.load(Ordering::SeqCst), tokens_before + 1);
        assert!(admin.values["production-admin/session_token"].starts_with("session-access-"));
        assert!(admin.store.is_none(), "same refresh token: nothing to store");
    }

    #[test]
    fn a_replaced_refresh_token_is_stored_and_a_dead_session_asks_to_sign_in() {
        let api = Arc::new(FakeAws::default());
        api.rotate.store(true, Ordering::SeqCst);
        let session = signed_in(&api);
        let meta = meta(suggest_profiles(&session.accounts(api.as_ref()).unwrap()));
        let stored = session.values();
        let provider = AwsProvider::new(api.clone());
        let later = now_secs() + 7200;

        let first = release(&provider, &meta, &stored, &["production-ro/access_key_id"], later).unwrap();
        let store = first.store.expect("AWS replaced the refresh token");
        assert_ne!(store[REFRESH_TOKEN], stored[REFRESH_TOKEN]);
        // The old stored values are stale, but the device remembers the new token.
        release(&provider, &meta, &stored, &["development-admin/access_key_id"], later + 7200).unwrap();

        api.session_alive.store(false, Ordering::SeqCst);
        let refused = release(&provider, &meta, &store, &["production-admin/access_key_id"], later + 4 * 7200);
        assert!(matches!(refused, Err(Refusal::SignInNeeded(_))));
    }

    #[test]
    fn requests_name_one_known_profile() {
        let api = Arc::new(FakeAws::default());
        let session = signed_in(&api);
        let meta = meta(suggest_profiles(&session.accounts(api.as_ref()).unwrap()));
        let provider = AwsProvider::new(api.clone());
        let stored = session.values();
        for fields in [
            &["staging-admin/access_key_id"][..],
            &["production-ro/access_key_id", "production-admin/secret_access_key"],
            &["production-ro/refresh_token"],
            &["access_token"],
        ] {
            assert!(matches!(release(&provider, &meta, &stored, fields, now_secs()), Err(Refusal::Failed(_))), "{fields:?}");
        }
    }

    #[test]
    fn expiry_is_rfc3339() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_795_000_000), "2026-11-18T11:06:40Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn errors_are_sorted() {
        let pending = json!({"error": "authorization_pending"});
        assert_eq!(classify(400, "", &pending), AwsError::Pending);
        assert!(matches!(classify(400, "", &json!({"error": "invalid_grant"})), AwsError::SignInNeeded(_)));
        assert!(matches!(classify(401, "UnauthorizedException:http://x", &Value::Null), AwsError::SignInNeeded(_)));
        assert!(matches!(classify(403, "ForbiddenException", &json!({"message": "No access"})), AwsError::Failed(m) if m.contains("No access")));
    }
}

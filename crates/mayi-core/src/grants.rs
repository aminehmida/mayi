//! Approvals that stay valid for a while. Held in memory only.

use crate::model::SecretValues;

/// How far a single approval reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantScope {
    /// This request only.
    Once,
    /// The same command again in the same session.
    SessionCommand,
    /// Any command in the same session.
    SessionAny,
}

#[derive(Clone)]
pub struct Grant {
    pub id: u64,
    pub item_id: String,
    pub item_version: u64,
    pub requester: String,
    pub session: String,
    /// `None` covers any command.
    pub command: Option<String>,
    pub expires_at_ms: u64,
    /// Values unlocked by a biometric check, kept for the grant's lifetime.
    pub values: Option<SecretValues>,
}

#[derive(Default)]
pub struct GrantStore {
    next_id: u64,
    grants: Vec<Grant>,
}

impl GrantStore {
    pub fn add(&mut self, mut grant: Grant) -> u64 {
        self.next_id += 1;
        grant.id = self.next_id;
        self.grants.push(grant);
        self.next_id
    }

    /// A live grant covering this exact use, if any. Drops expired grants.
    pub fn find(
        &mut self,
        item_id: &str,
        item_version: u64,
        requester: &str,
        session: &str,
        command: &str,
        now_ms: u64,
    ) -> Option<Grant> {
        self.grants.retain(|g| g.expires_at_ms > now_ms);
        self.grants
            .iter()
            .find(|g| {
                g.item_id == item_id
                    && g.item_version == item_version
                    && g.requester == requester
                    && g.session == session
                    && g.command.as_deref().is_none_or(|c| c == command)
            })
            .cloned()
    }

    /// Revokes every grant of a session. Returns how many were removed.
    pub fn revoke_session(&mut self, requester: &str, session: &str) -> usize {
        let before = self.grants.len();
        self.grants.retain(|g| !(g.requester == requester && g.session == session));
        before - self.grants.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(command: Option<&str>, expires_at_ms: u64) -> Grant {
        Grant {
            id: 0,
            item_id: "item".into(),
            item_version: 1,
            requester: "local".into(),
            session: "s1".into(),
            command: command.map(String::from),
            expires_at_ms,
            values: None,
        }
    }

    #[test]
    fn matching_and_expiry() {
        let mut store = GrantStore::default();
        store.add(grant(Some("make deploy"), 1000));
        let find = |s: &mut GrantStore, version, requester, session, command, now| {
            s.find("item", version, requester, session, command, now).is_some()
        };
        assert!(find(&mut store, 1, "local", "s1", "make deploy", 999));
        assert!(!find(&mut store, 1, "local", "s1", "make destroy", 999));
        assert!(!find(&mut store, 1, "local", "s2", "make deploy", 999));
        assert!(!find(&mut store, 1, "vm", "s1", "make deploy", 999));
        assert!(!find(&mut store, 2, "local", "s1", "make deploy", 999), "replaced secret");
        assert!(!find(&mut store, 1, "local", "s1", "make deploy", 1000), "expired");
        assert!(!find(&mut store, 1, "local", "s1", "make deploy", 999), "expired grants are dropped");
    }

    #[test]
    fn any_command_and_revoke() {
        let mut store = GrantStore::default();
        store.add(grant(None, 1000));
        store.add(grant(Some("x"), 1000));
        assert!(store.find("item", 1, "local", "s1", "anything", 1).is_some());
        assert_eq!(store.revoke_session("local", "other"), 0);
        assert_eq!(store.revoke_session("local", "s1"), 2);
        assert!(store.find("item", 1, "local", "s1", "anything", 1).is_none());
    }
}

//! Who may do what to this device. Incoming streams fall into three access
//! groups, ordered by risk; each member gets a rule per group, decided by
//! this device alone. The rules live in the device's own state directory
//! (`access.json`, sealed when a storage key is set) and never in the
//! group state or adverts, so no other member learns who is trusted.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nostr::prelude::PublicKey;
use serde::{Deserialize, Serialize};

const FILE: &str = "access.json";

/// What an incoming stream asks to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Group {
    /// Send me things: files, chat, clipboard.
    Send,
    /// Use my services: forwards to the default service and served ports.
    Services,
    /// Control this device: terminal, later screen view and control.
    Control,
}

impl Group {
    pub const ALL: [Group; 3] = [Group::Send, Group::Services, Group::Control];

    /// The name used in the CLI and settings (`send`, `services`, `control`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Group::Send => "send",
            Group::Services => "services",
            Group::Control => "control",
        }
    }

    /// The inverse of [`Group::name`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Group> {
        Group::ALL.into_iter().find(|g| g.name().eq_ignore_ascii_case(s.trim()))
    }

    /// Today's behavior for the first two groups; Control asks.
    #[must_use]
    pub fn default_rule(self) -> Rule {
        match self {
            Group::Send | Group::Services => Rule::Allow,
            Group::Control => Rule::Ask,
        }
    }
}

/// A member's rule for one group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rule {
    Allow,
    Deny,
    /// Ask on first use (Control only): the host decides each request.
    Ask,
}

impl Rule {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Rule::Allow => "allow",
            Rule::Deny => "deny",
            Rule::Ask => "ask",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("only control can be set to ask")]
    AskOutsideControl,
    #[error("access settings: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Rules(BTreeMap<Group, Rule>);

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Settings {
    /// Rules for every member without one of its own.
    #[serde(default)]
    defaults: Rules,
    /// Per member (hex public key).
    #[serde(default)]
    devices: BTreeMap<String, Rules>,
}

/// The rules, loaded from and saved to a state directory.
#[derive(Debug)]
pub struct Access {
    path: Option<PathBuf>,
    settings: Settings,
}

impl Access {
    /// Load `dir/access.json`; missing means every default. An unreadable
    /// file is an error rather than a silent reset to the defaults, which
    /// could allow what the owner denied.
    pub fn load(dir: &Path) -> Result<Self, AccessError> {
        let path = dir.join(FILE);
        let settings = match crate::fsutil::read_secret(&path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Settings::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path: Some(path), settings })
    }

    /// Rules kept in memory only (tests, a client without a directory).
    #[must_use]
    pub fn in_memory() -> Self {
        Self { path: None, settings: Settings::default() }
    }

    /// The rule for every member without one of its own.
    #[must_use]
    pub fn default_rule(&self, group: Group) -> Rule {
        self.settings.defaults.0.get(&group).copied().unwrap_or_else(|| group.default_rule())
    }

    /// The rule that applies to `device` for `group`.
    #[must_use]
    pub fn rule(&self, device: &PublicKey, group: Group) -> Rule {
        self.own_rule(device, group).unwrap_or_else(|| self.default_rule(group))
    }

    /// `device`'s own rule for `group`, if it has one.
    #[must_use]
    pub fn own_rule(&self, device: &PublicKey, group: Group) -> Option<Rule> {
        self.settings.devices.get(&device.to_hex()).and_then(|r| r.0.get(&group).copied())
    }

    /// Members with a rule of their own.
    #[must_use]
    pub fn devices(&self) -> Vec<PublicKey> {
        self.settings.devices.keys().filter_map(|k| PublicKey::from_hex(k).ok()).collect()
    }

    /// Set `device`'s rule for `group` (`None` device: the default for
    /// everyone; `None` rule: back to the default) and save.
    pub fn set(&mut self, device: Option<&PublicKey>, group: Group, rule: Option<Rule>) -> Result<(), AccessError> {
        if rule == Some(Rule::Ask) && group != Group::Control {
            return Err(AccessError::AskOutsideControl);
        }
        let mut next = self.settings.clone();
        match device {
            None => match rule {
                Some(r) if r != group.default_rule() => {
                    next.defaults.0.insert(group, r);
                }
                _ => {
                    next.defaults.0.remove(&group);
                }
            },
            Some(d) => {
                let key = d.to_hex();
                let rules = next.devices.entry(key.clone()).or_default();
                match rule {
                    Some(r) => {
                        rules.0.insert(group, r);
                    }
                    None => {
                        rules.0.remove(&group);
                    }
                }
                if rules.0.is_empty() {
                    next.devices.remove(&key);
                }
            }
        }
        self.save(next)
    }

    /// Drop every rule of `device`'s own and save.
    pub fn reset(&mut self, device: &PublicKey) -> Result<(), AccessError> {
        let mut next = self.settings.clone();
        next.devices.remove(&device.to_hex());
        self.save(next)
    }

    fn save(&mut self, next: Settings) -> Result<(), AccessError> {
        if next == self.settings {
            return Ok(());
        }
        if let Some(path) = &self.path {
            let json = serde_json::to_vec_pretty(&next).map_err(std::io::Error::other)?;
            crate::fsutil::write_secret(path, &json)?;
        }
        self.settings = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk() -> PublicKey {
        crate::Identity::generate().public_key()
    }

    #[test]
    fn defaults_keep_todays_behavior_and_control_asks() {
        let a = Access::in_memory();
        let d = pk();
        assert_eq!(a.rule(&d, Group::Send), Rule::Allow);
        assert_eq!(a.rule(&d, Group::Services), Rule::Allow);
        assert_eq!(a.rule(&d, Group::Control), Rule::Ask);
    }

    #[test]
    fn a_members_rule_beats_the_default_and_ask_is_control_only() {
        let mut a = Access::in_memory();
        let (d, e) = (pk(), pk());
        a.set(None, Group::Send, Some(Rule::Deny)).unwrap();
        a.set(Some(&d), Group::Send, Some(Rule::Allow)).unwrap();
        assert_eq!(a.rule(&d, Group::Send), Rule::Allow);
        assert_eq!(a.rule(&e, Group::Send), Rule::Deny);
        assert!(matches!(a.set(Some(&d), Group::Services, Some(Rule::Ask)), Err(AccessError::AskOutsideControl)));
        a.set(Some(&d), Group::Send, None).unwrap();
        assert_eq!(a.rule(&d, Group::Send), Rule::Deny);
        assert!(a.devices().is_empty(), "a member with no rules left is dropped");
    }

    #[test]
    fn rules_survive_a_restart_and_a_bad_file_is_an_error() {
        let dir = std::env::temp_dir().join(format!("noscat-access-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let d = pk();
        let mut a = Access::load(&dir).unwrap();
        a.set(Some(&d), Group::Control, Some(Rule::Allow)).unwrap();
        a.set(None, Group::Services, Some(Rule::Deny)).unwrap();
        let b = Access::load(&dir).unwrap();
        assert_eq!(b.rule(&d, Group::Control), Rule::Allow);
        assert_eq!(b.default_rule(Group::Services), Rule::Deny);
        assert_eq!(b.devices(), vec![d]);
        std::fs::write(dir.join(FILE), b"{not json").unwrap();
        assert!(Access::load(&dir).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}

//! Authorized-scope allowlist and enforcement.
//!
//! Scope is the tool's single most important safety property: it is the guard
//! that keeps a scan from ever touching an address the operator was not
//! authorized to assess. Enforcement is applied *after* target expansion and
//! *before* any packet is sent — every resolved IP must fall inside the scope
//! or it is refused and logged.
//!
//! An empty scope means "no allowlist configured". In this phase that is
//! permitted (with a loud warning); a later phase promotes it to a hard,
//! required authorization gate.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::config::target::resolve_host;
use crate::error::{Error, Result};

/// A parsed scope entry.
#[derive(Debug, Clone)]
enum ScopeEntry {
    Net(IpNet),
    Ip(IpAddr),
}

/// The authorized allowlist. Enforcement is IP-based: hostnames provided as
/// scope entries are resolved to addresses when the scope is built.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    entries: Vec<ScopeEntry>,
    /// The original textual entries, retained for reporting/audit.
    raw: Vec<String>,
}

impl Scope {
    /// Build a scope from textual entries (CIDR, IP, or hostname). Hostnames are
    /// resolved to their addresses. An empty input yields an empty scope.
    pub async fn build(entries: &[String]) -> Result<Scope> {
        let mut scope = Scope::default();
        for entry in entries {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            scope.raw.push(entry.to_string());

            if entry.contains('/') {
                let net = entry.parse::<IpNet>().map_err(|e| Error::ScopeParse {
                    entry: entry.to_string(),
                    reason: format!("not a valid CIDR: {e}"),
                })?;
                scope.entries.push(ScopeEntry::Net(net));
            } else if let Ok(ip) = entry.parse::<IpAddr>() {
                scope.entries.push(ScopeEntry::Ip(ip));
            } else {
                // Treat as a hostname and pin its resolved addresses.
                let ips = resolve_host(entry).await.map_err(|_| Error::ScopeParse {
                    entry: entry.to_string(),
                    reason: "not a CIDR/IP and could not be resolved as a hostname".into(),
                })?;
                scope.entries.extend(ips.into_iter().map(ScopeEntry::Ip));
            }
        }
        Ok(scope)
    }

    /// Whether any scope entry was configured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The original textual scope entries (for report metadata).
    pub fn raw(&self) -> &[String] {
        &self.raw
    }

    /// Whether an address is authorized. An empty scope authorizes everything
    /// (the caller is responsible for warning in that case).
    pub fn allows(&self, ip: &IpAddr) -> bool {
        if self.entries.is_empty() {
            return true;
        }
        self.entries.iter().any(|e| match e {
            ScopeEntry::Ip(a) => a == ip,
            ScopeEntry::Net(net) => net.contains(ip),
        })
    }

    /// Partition addresses into `(allowed, refused)`. Refused addresses are the
    /// ones that must never be probed.
    pub fn partition(&self, ips: Vec<IpAddr>) -> (Vec<IpAddr>, Vec<IpAddr>) {
        ips.into_iter().partition(|ip| self.allows(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_scope_allows_all() {
        let scope = Scope::build(&[]).await.unwrap();
        assert!(scope.is_empty());
        assert!(scope.allows(&IpAddr::from([8, 8, 8, 8])));
    }

    #[tokio::test]
    async fn cidr_scope_enforced() {
        let scope = Scope::build(&["10.0.0.0/24".to_string()]).await.unwrap();
        assert!(scope.allows(&IpAddr::from([10, 0, 0, 5])));
        assert!(!scope.allows(&IpAddr::from([10, 0, 1, 5])));
        assert!(!scope.allows(&IpAddr::from([8, 8, 8, 8])));
    }

    #[tokio::test]
    async fn single_ip_scope() {
        let scope = Scope::build(&["192.168.1.10".to_string()]).await.unwrap();
        assert!(scope.allows(&IpAddr::from([192, 168, 1, 10])));
        assert!(!scope.allows(&IpAddr::from([192, 168, 1, 11])));
    }

    #[tokio::test]
    async fn partition_splits_in_and_out_of_scope() {
        let scope = Scope::build(&["10.0.0.0/24".to_string()]).await.unwrap();
        let (allowed, refused) = scope.partition(vec![
            IpAddr::from([10, 0, 0, 1]),
            IpAddr::from([10, 0, 1, 1]),
        ]);
        assert_eq!(allowed, vec![IpAddr::from([10, 0, 0, 1])]);
        assert_eq!(refused, vec![IpAddr::from([10, 0, 1, 1])]);
    }

    #[tokio::test]
    async fn rejects_bad_scope_entry() {
        assert!(Scope::build(&["not a cidr!!".to_string()]).await.is_err());
    }
}

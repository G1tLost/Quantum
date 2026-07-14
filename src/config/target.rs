//! Target parsing and expansion.
//!
//! Parsing ([`parse_target_token`]) is synchronous and pure, so it is fully
//! unit-testable. Expansion ([`resolve_and_expand`]) is async because hostname
//! resolution hits DNS; it also enforces the `--max-targets` safety cap so a
//! fat CIDR (e.g. a /8) can never silently balloon into millions of hosts.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::error::{Error, Result};

/// A parsed but not-yet-expanded target expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSpec {
    /// A single literal IP address.
    Ip(IpAddr),
    /// A CIDR block; expansion yields its host addresses.
    Cidr(IpNet),
    /// An inclusive address range `[start, end]` (same IP family).
    Range { start: IpAddr, end: IpAddr },
    /// A hostname to be resolved via DNS at expansion time.
    Host(String),
}

impl TargetSpec {
    /// A conservative upper bound on the number of hosts this spec expands to.
    /// Returns `None` for hostnames (unknown until resolved).
    fn estimated_hosts(&self) -> Option<u128> {
        match self {
            TargetSpec::Ip(_) => Some(1),
            TargetSpec::Host(_) => None,
            TargetSpec::Cidr(net) => match net {
                // `hosts()` excludes network/broadcast for prefixes < /31.
                IpNet::V4(v4) => {
                    let bits = 32 - u32::from(v4.prefix_len());
                    Some(host_count_v4(bits))
                }
                IpNet::V6(v6) => {
                    let bits = 128 - u32::from(v6.prefix_len());
                    Some(1u128.checked_shl(bits.min(127)).unwrap_or(u128::MAX))
                }
            },
            TargetSpec::Range { start, end } => range_len(*start, *end),
        }
    }
}

fn host_count_v4(host_bits: u32) -> u128 {
    match host_bits {
        0 => 1,                // /32 -> single host
        1 => 2,                // /31 -> two usable hosts
        n => (1u128 << n) - 2, // exclude network + broadcast
    }
}

fn range_len(start: IpAddr, end: IpAddr) -> Option<u128> {
    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => {
            let (s, e) = (u32::from(s), u32::from(e));
            (e >= s).then(|| u128::from(e - s) + 1)
        }
        (IpAddr::V6(s), IpAddr::V6(e)) => {
            let (s, e) = (u128::from(s), u128::from(e));
            (e >= s).then(|| (e - s).saturating_add(1))
        }
        _ => None,
    }
}

/// Parse one target token into a [`TargetSpec`].
///
/// Recognizes, in order: CIDR (`contains '/'`), range (`contains '-'`), a bare
/// IP literal, and finally a hostname.
pub fn parse_target_token(token: &str) -> Result<TargetSpec> {
    let token = token.trim();
    if token.is_empty() {
        return Err(Error::TargetParse {
            token: token.to_string(),
            reason: "empty target".into(),
        });
    }

    if token.contains('/') {
        return token
            .parse::<IpNet>()
            .map(TargetSpec::Cidr)
            .map_err(|e| Error::TargetParse {
                token: token.to_string(),
                reason: format!("not a valid CIDR: {e}"),
            });
    }

    if let Some(spec) = parse_range(token)? {
        return Ok(spec);
    }

    if let Ok(ip) = token.parse::<IpAddr>() {
        return Ok(TargetSpec::Ip(ip));
    }

    if is_plausible_hostname(token) {
        return Ok(TargetSpec::Host(token.to_string()));
    }

    Err(Error::TargetParse {
        token: token.to_string(),
        reason: "not an IP, CIDR, range, or valid hostname".into(),
    })
}

/// Parse a range token like `10.0.0.1-10.0.0.50` or the last-octet shorthand
/// `10.0.0.1-50`. Returns `Ok(None)` when the token is not range-shaped so the
/// caller can fall through to IP/hostname parsing (hostnames may contain `-`).
fn parse_range(token: &str) -> Result<Option<TargetSpec>> {
    let Some((left, right)) = token.split_once('-') else {
        return Ok(None);
    };
    let (left, right) = (left.trim(), right.trim());

    // Left side must be a literal IP for this to be a range.
    let Ok(start) = left.parse::<IpAddr>() else {
        return Ok(None);
    };

    let end = if let Ok(end) = right.parse::<IpAddr>() {
        end
    } else if let (IpAddr::V4(s), Ok(last)) = (start, right.parse::<u8>()) {
        // Last-octet shorthand: keep the first three octets from `start`.
        let o = s.octets();
        IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], last))
    } else {
        return Err(Error::TargetParse {
            token: token.to_string(),
            reason: "range end must be an IP address or (for IPv4) a final-octet number".into(),
        });
    };

    match (start, end) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {}
        _ => {
            return Err(Error::TargetParse {
                token: token.to_string(),
                reason: "range endpoints must be the same IP family".into(),
            })
        }
    }

    if range_len(start, end).is_none() {
        return Err(Error::TargetParse {
            token: token.to_string(),
            reason: "range end is before range start".into(),
        });
    }

    Ok(Some(TargetSpec::Range { start, end }))
}

/// A permissive hostname sanity check (RFC 1123-ish). We keep it lenient — DNS
/// is the real authority — but reject obviously bogus tokens early.
fn is_plausible_hostname(token: &str) -> bool {
    if token.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = token.split('.').collect();

    // The rightmost label (the TLD) must not be entirely numeric. Per RFC 1123
    // no real TLD is all-digits, and this is what disambiguates a hostname from
    // a dotted-decimal look-alike: it rejects junk like "999.999.999.999" or
    // "10.0.0.256" (invalid IPs) that would otherwise slip through as hostnames.
    let tld_all_numeric = labels
        .last()
        .is_some_and(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_digit()));
    if tld_all_numeric {
        return false;
    }

    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Expand a set of specs into concrete IP addresses, resolving hostnames via DNS
/// and enforcing the `max` safety cap. Duplicate addresses are removed while
/// preserving first-seen order.
pub async fn resolve_and_expand(specs: &[TargetSpec], max: usize) -> Result<Vec<IpAddr>> {
    // Fail fast on obviously oversized expansions before materializing anything.
    let estimate: u128 = specs
        .iter()
        .filter_map(TargetSpec::estimated_hosts)
        .fold(0u128, |acc, n| acc.saturating_add(n));
    if estimate > max as u128 {
        return Err(Error::TooManyTargets {
            count: estimate.min(u128::from(u32::MAX)) as usize,
            cap: max,
        });
    }

    let mut out: Vec<IpAddr> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push = |ip: IpAddr, out: &mut Vec<IpAddr>| -> Result<()> {
        if seen.insert(ip) {
            if out.len() >= max {
                return Err(Error::TooManyTargets {
                    count: out.len() + 1,
                    cap: max,
                });
            }
            out.push(ip);
        }
        Ok(())
    };

    for spec in specs {
        match spec {
            TargetSpec::Ip(ip) => push(*ip, &mut out)?,
            TargetSpec::Cidr(net) => match net {
                IpNet::V4(v4) => {
                    for ip in v4.hosts() {
                        push(IpAddr::V4(ip), &mut out)?;
                    }
                }
                IpNet::V6(v6) => {
                    for ip in v6.hosts() {
                        push(IpAddr::V6(ip), &mut out)?;
                    }
                }
            },
            TargetSpec::Range { start, end } => {
                for ip in iter_range(*start, *end) {
                    push(ip, &mut out)?;
                }
            }
            TargetSpec::Host(host) => {
                for ip in resolve_host(host).await? {
                    push(ip, &mut out)?;
                }
            }
        }
    }

    Ok(out)
}

/// Iterate every address in an inclusive range. Assumes same family and
/// `end >= start` (validated at parse time).
fn iter_range(start: IpAddr, end: IpAddr) -> Box<dyn Iterator<Item = IpAddr>> {
    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => {
            Box::new((u32::from(s)..=u32::from(e)).map(|n| IpAddr::V4(Ipv4Addr::from(n))))
        }
        (IpAddr::V6(s), IpAddr::V6(e)) => {
            Box::new((u128::from(s)..=u128::from(e)).map(|n| IpAddr::V6(Ipv6Addr::from(n))))
        }
        // Mixed families are rejected at parse time; yield nothing defensively.
        _ => Box::new(std::iter::empty()),
    }
}

/// Resolve a hostname to its A/AAAA addresses via the system resolver.
pub async fn resolve_host(host: &str) -> Result<Vec<IpAddr>> {
    // `lookup_host` needs a port; 0 is fine, we only keep the IPs.
    let iter = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|e| Error::DnsResolution {
            host: host.to_string(),
            reason: e.to_string(),
        })?;
    let ips: Vec<IpAddr> = {
        let mut seen = std::collections::HashSet::new();
        iter.map(|sa| sa.ip())
            .filter(|ip| seen.insert(*ip))
            .collect()
    };
    if ips.is_empty() {
        return Err(Error::DnsResolution {
            host: host.to_string(),
            reason: "no addresses returned".into(),
        });
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parses_single_ipv4() {
        assert_eq!(
            parse_target_token("192.168.1.1").unwrap(),
            TargetSpec::Ip(IpAddr::from([192, 168, 1, 1]))
        );
    }

    #[test]
    fn parses_single_ipv6() {
        assert_eq!(
            parse_target_token("::1").unwrap(),
            TargetSpec::Ip(IpAddr::from_str("::1").unwrap())
        );
    }

    #[test]
    fn parses_cidr() {
        let spec = parse_target_token("10.0.0.0/24").unwrap();
        assert!(matches!(spec, TargetSpec::Cidr(_)));
        assert_eq!(spec.estimated_hosts(), Some(254));
    }

    #[test]
    fn parses_full_range() {
        let spec = parse_target_token("10.0.0.5-10.0.0.9").unwrap();
        assert_eq!(
            spec,
            TargetSpec::Range {
                start: IpAddr::from([10, 0, 0, 5]),
                end: IpAddr::from([10, 0, 0, 9]),
            }
        );
        assert_eq!(spec.estimated_hosts(), Some(5));
    }

    #[test]
    fn parses_last_octet_shorthand() {
        let spec = parse_target_token("172.16.0.10-20").unwrap();
        assert_eq!(
            spec,
            TargetSpec::Range {
                start: IpAddr::from([172, 16, 0, 10]),
                end: IpAddr::from([172, 16, 0, 20]),
            }
        );
        assert_eq!(spec.estimated_hosts(), Some(11));
    }

    #[test]
    fn rejects_reversed_range() {
        assert!(parse_target_token("10.0.0.9-10.0.0.1").is_err());
    }

    #[test]
    fn parses_hostname() {
        assert_eq!(
            parse_target_token("scanme.example.com").unwrap(),
            TargetSpec::Host("scanme.example.com".into())
        );
    }

    #[test]
    fn rejects_garbage() {
        // Dotted-decimal look-alikes that are not valid IPs must not slip
        // through as hostnames (their TLD label is all-numeric).
        assert!(parse_target_token("999.999.999.999").is_err());
        assert!(parse_target_token("10.0.0.256").is_err());
        assert!(parse_target_token("42").is_err());
        // A label starting with '-' is not a valid hostname label.
        assert!(parse_target_token("--not-a-host").is_err());
    }

    #[test]
    fn accepts_real_hostnames() {
        assert!(matches!(
            parse_target_token("localhost"),
            Ok(TargetSpec::Host(_))
        ));
        // Numeric leading labels are fine as long as the TLD is not all-numeric.
        assert!(matches!(
            parse_target_token("3com.example.com"),
            Ok(TargetSpec::Host(_))
        ));
    }

    #[tokio::test]
    async fn expands_range_and_dedupes() {
        let specs = vec![
            parse_target_token("10.0.0.1-10.0.0.3").unwrap(),
            parse_target_token("10.0.0.2").unwrap(), // duplicate
        ];
        let ips = resolve_and_expand(&specs, 1000).await.unwrap();
        assert_eq!(
            ips,
            vec![
                IpAddr::from([10, 0, 0, 1]),
                IpAddr::from([10, 0, 0, 2]),
                IpAddr::from([10, 0, 0, 3]),
            ]
        );
    }

    #[tokio::test]
    async fn enforces_max_targets_cap() {
        let specs = vec![parse_target_token("10.0.0.0/16").unwrap()];
        let err = resolve_and_expand(&specs, 100).await.unwrap_err();
        assert!(matches!(err, Error::TooManyTargets { cap: 100, .. }));
    }
}

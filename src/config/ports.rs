//! Port-specification parsing.
//!
//! Supports comma-separated lists and inclusive ranges (`22,80,443,8000-8100`),
//! `--top-ports N` (a built-in frequency-ordered list), and `--all-ports`
//! (1-65535). All paths return a sorted, de-duplicated `Vec<u16>` with port 0
//! rejected.

use crate::error::{Error, Result};

/// The most common TCP ports, in rough open-frequency order (nmap-style).
///
/// `--top-ports N` takes the first `N` of these. Phase 2 will expand this to the
/// full top-1000 data set; today it covers the ~100 ports that carry the vast
/// majority of real-world services.
pub const TOP_PORTS: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000,
    8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156,
    543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
    13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
];

/// Parse a `--ports` specification string into a sorted, de-duplicated list.
pub fn parse_port_spec(spec: &str) -> Result<Vec<u16>> {
    let mut ports: Vec<u16> = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = part.split_once('-') {
            let lo = parse_port(lo.trim(), spec)?;
            let hi = parse_port(hi.trim(), spec)?;
            if lo > hi {
                return Err(Error::PortParse {
                    spec: spec.to_string(),
                    reason: format!("range {lo}-{hi} is reversed"),
                });
            }
            ports.extend(lo..=hi);
        } else {
            ports.push(parse_port(part, spec)?);
        }
    }
    finalize(ports, spec)
}

/// The first `n` ports of [`TOP_PORTS`]. Clamps to the list length.
pub fn top_ports(n: usize) -> Result<Vec<u16>> {
    if n == 0 {
        return Err(Error::PortParse {
            spec: format!("--top-ports {n}"),
            reason: "must be at least 1".into(),
        });
    }
    let take = n.min(TOP_PORTS.len());
    if take < n {
        tracing::warn!(
            requested = n,
            available = TOP_PORTS.len(),
            "requested more top-ports than are in the built-in list; using all available"
        );
    }
    let mut ports = TOP_PORTS[..take].to_vec();
    ports.sort_unstable();
    Ok(ports)
}

/// Every TCP port, 1-65535.
pub fn all_ports() -> Vec<u16> {
    (1..=u16::MAX).collect()
}

fn parse_port(s: &str, spec: &str) -> Result<u16> {
    let p: u32 = s.parse().map_err(|_| Error::PortParse {
        spec: spec.to_string(),
        reason: format!("'{s}' is not a number"),
    })?;
    if p == 0 || p > u32::from(u16::MAX) {
        return Err(Error::PortParse {
            spec: spec.to_string(),
            reason: format!("port {p} out of range (1-65535)"),
        });
    }
    Ok(p as u16)
}

fn finalize(mut ports: Vec<u16>, spec: &str) -> Result<Vec<u16>> {
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err(Error::PortParse {
            spec: spec.to_string(),
            reason: "no ports selected".into(),
        });
    }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_list() {
        assert_eq!(parse_port_spec("80,443,22").unwrap(), vec![22, 80, 443]);
    }

    #[test]
    fn parses_range() {
        assert_eq!(parse_port_spec("20-23").unwrap(), vec![20, 21, 22, 23]);
    }

    #[test]
    fn parses_mixed_and_dedupes() {
        assert_eq!(
            parse_port_spec("22,80,79-81,443").unwrap(),
            vec![22, 79, 80, 81, 443]
        );
    }

    #[test]
    fn rejects_zero() {
        assert!(parse_port_spec("0").is_err());
        assert!(parse_port_spec("0-10").is_err());
    }

    #[test]
    fn rejects_overflow() {
        assert!(parse_port_spec("70000").is_err());
    }

    #[test]
    fn rejects_reversed_range() {
        assert!(parse_port_spec("100-50").is_err());
    }

    #[test]
    fn top_ports_takes_prefix_sorted() {
        let p = top_ports(3).unwrap();
        assert_eq!(p.len(), 3);
        // First three of TOP_PORTS are 80, 23, 443 -> sorted.
        assert_eq!(p, vec![23, 80, 443]);
    }

    #[test]
    fn top_ports_clamps() {
        let p = top_ports(100_000).unwrap();
        assert_eq!(p.len(), TOP_PORTS.len());
    }

    #[test]
    fn all_ports_is_full_range() {
        assert_eq!(all_ports().len(), 65535);
    }
}

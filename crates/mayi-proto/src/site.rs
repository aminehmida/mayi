//! The websites a login may be typed into, and the origins browsers report.
//!
//! A login lists its sites as hosts: `github.com`, `*.example.com` for every
//! subdomain (not the domain itself), each with an optional port. A page
//! matches only over https; plain http is accepted for this machine alone
//! (`localhost`, `*.localhost`, `127.0.0.1`, `[::1]`), for local development.

use std::fmt;

/// A page's origin as the browser reports it: scheme, host and port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub scheme: String,
    /// Lowercase ASCII; an IPv6 address keeps its brackets.
    pub host: String,
    pub port: u16,
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "http" { 80 } else { 443 }
}

fn is_local(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || host == "[::1]"
}

/// Splits `host[:port]`, minding the colons inside an IPv6 address.
fn split_port(text: &str) -> Result<(&str, Option<u16>), String> {
    let (host, port) = if text.starts_with('[') {
        let end = text.find(']').ok_or("unclosed [ in the address")?;
        let rest = &text[end + 1..];
        match rest.strip_prefix(':') {
            Some(port) => (&text[..=end], Some(port)),
            None if rest.is_empty() => (&text[..=end], None),
            None => return Err(format!("unexpected {rest:?} after the address")),
        }
    } else {
        match text.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (text, None),
        }
    };
    let port = match port {
        Some(p) => Some(p.parse::<u16>().ok().filter(|&p| p > 0).ok_or(format!("{p:?} is not a port"))?),
        None => None,
    };
    Ok((host, port))
}

fn valid_host(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return !inner.is_empty() && inner.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
    }
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Takes the `host[:port]` part out of an address, dropping scheme, path,
/// query and fragment.
fn authority(text: &str) -> Result<(Option<String>, &str), String> {
    let (scheme, rest) = match text.split_once("://") {
        Some((scheme, rest)) => (Some(scheme.to_ascii_lowercase()), rest),
        None => (None, text),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.contains('@') {
        return Err("an address with a user name in it is not accepted".into());
    }
    Ok((scheme, authority))
}

impl Origin {
    /// Reads an origin or a full address, such as `https://github.com` or
    /// `https://github.com/login?x=1`. Refuses anything Mayi would not type a
    /// password into: other schemes, and plain http beyond this machine.
    pub fn parse(text: &str) -> Result<Origin, String> {
        let text = text.trim();
        if !text.is_ascii() {
            return Err(format!("{text:?} is not an address as a browser reports it"));
        }
        let (scheme, authority) = authority(text)?;
        let scheme = scheme.ok_or(format!("{text:?} is not a web address"))?;
        if scheme != "https" && scheme != "http" {
            return Err(format!("{text:?} is not a web page"));
        }
        let (host, port) = split_port(authority)?;
        let host = host.to_ascii_lowercase();
        if !valid_host(&host) {
            return Err(format!("{text:?} has no valid host"));
        }
        if scheme == "http" && !is_local(&host) {
            return Err(format!("{host} is served over plain http; Mayi only types logins into https pages"));
        }
        let port = port.unwrap_or(default_port(&scheme));
        Ok(Origin { scheme, host, port })
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.host)?;
        if self.port != default_port(&self.scheme) {
            write!(f, ":{}", self.port)?;
        }
        Ok(())
    }
}

/// Reduces a website as someone types or pastes it to the form a login
/// stores: `host`, `host:port`, `*.host` or `*.host:port`, lowercase.
pub fn normalize_site(text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("empty website".into());
    }
    if !text.is_ascii() {
        return Err(format!(
            "{text:?}: enter the website as the address bar shows it, with any accents in xn-- form"
        ));
    }
    let (_, authority) = authority(text)?;
    let lower = authority.to_ascii_lowercase();
    let (host, port) = split_port(&lower)?;
    let (wildcard, bare) = match host.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, host),
    };
    if !valid_host(bare) {
        return Err(format!("{text:?} is not a website"));
    }
    // `*.com` would cover every site under a top-level domain.
    if wildcard && !bare.contains('.') && bare != "localhost" {
        return Err(format!("{text:?} covers too much: name the domain, as in *.example.com"));
    }
    let port = port.filter(|&p| p != 443);
    Ok(match port {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// Whether a page at `origin` belongs to the stored `site`.
pub fn site_matches(site: &str, origin: &Origin) -> bool {
    let Ok((host, port)) = split_port(site) else { return false };
    let port_ok = match port {
        Some(port) => origin.port == port,
        None => origin.port == default_port(&origin.scheme),
    };
    let host_ok = match host.strip_prefix("*.") {
        Some(domain) => origin
            .host
            .strip_suffix(domain)
            .is_some_and(|sub| sub.len() > 1 && sub.ends_with('.')),
        None => origin.host == host,
    };
    // Plain http only ever reaches this machine; `Origin::parse` already
    // refuses it elsewhere, and this keeps a hand-built origin honest.
    let scheme_ok = origin.scheme == "https" || (origin.scheme == "http" && is_local(&origin.host));
    port_ok && host_ok && scheme_ok
}

pub fn matches_any(sites: &[String], origin: &Origin) -> bool {
    sites.iter().any(|site| site_matches(site, origin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins() {
        let o = Origin::parse("https://GitHub.com/login?return_to=x#top").unwrap();
        assert_eq!((o.scheme.as_str(), o.host.as_str(), o.port), ("https", "github.com", 443));
        assert_eq!(o.to_string(), "https://github.com");
        assert_eq!(Origin::parse("https://example.com:8443").unwrap().to_string(), "https://example.com:8443");
        assert_eq!(Origin::parse("http://127.0.0.1:8765").unwrap().to_string(), "http://127.0.0.1:8765");
        assert_eq!(Origin::parse("http://[::1]:3000/").unwrap().host, "[::1]");
        assert_eq!(Origin::parse("http://app.localhost").unwrap().port, 80);
        for bad in [
            "http://github.com",
            "ftp://github.com",
            "github.com",
            "null",
            "data:text/html,hi",
            "https://user:pw@github.com",
            "https://exa mple.com",
            "https://example.com:0",
            "https://example.com:99999",
            "https://bücher.de",
            "https://",
        ] {
            assert!(Origin::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn sites_are_normalized() {
        let ok = [
            ("github.com", "github.com"),
            ("  GitHub.com ", "github.com"),
            ("https://github.com/login", "github.com"),
            ("https://github.com:443/", "github.com"),
            ("*.Example.com", "*.example.com"),
            ("example.com:8443", "example.com:8443"),
            ("localhost:8765", "localhost:8765"),
            ("*.localhost", "*.localhost"),
            ("127.0.0.1:9000", "127.0.0.1:9000"),
            ("xn--bcher-kva.de", "xn--bcher-kva.de"),
        ];
        for (input, want) in ok {
            assert_eq!(normalize_site(input).unwrap(), want, "{input:?}");
        }
        for bad in ["", "*.com", "*", "exa*mple.com", "bücher.de", "a..b", "-a.com", "me@github.com", "a.com:x"] {
            assert!(normalize_site(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn matching() {
        let o = |text: &str| Origin::parse(text).unwrap();
        let cases = [
            ("github.com", "https://github.com", true),
            ("github.com", "https://github.com:8443", false),
            ("github.com", "https://gist.github.com", false),
            ("github.com", "https://github.com.evil.example", false),
            ("github.com", "https://evilgithub.com", false),
            ("*.github.com", "https://gist.github.com", true),
            ("*.github.com", "https://a.b.github.com", true),
            ("*.github.com", "https://github.com", false),
            ("*.github.com", "https://evilgithub.com", false),
            ("example.com:8443", "https://example.com:8443", true),
            ("example.com:8443", "https://example.com", false),
            ("127.0.0.1:8765", "http://127.0.0.1:8765", true),
            ("127.0.0.1:8765", "http://127.0.0.1:8766", false),
            ("localhost", "http://localhost", true),
            ("localhost", "https://localhost", true),
            ("*.localhost", "http://app.localhost", true),
        ];
        for (site, origin, want) in cases {
            assert_eq!(site_matches(site, &o(origin)), want, "{site} vs {origin}");
        }
        let forged = Origin { scheme: "http".into(), host: "github.com".into(), port: 80 };
        assert!(!site_matches("github.com:80", &forged), "plain http beyond this machine never matches");
        assert!(matches_any(&["a.com".into(), "github.com".into()], &o("https://github.com")));
        assert!(!matches_any(&[], &o("https://github.com")));
    }
}

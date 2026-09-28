//! The bytes a proxy client sends and expects back: SOCKS5 (RFC 1928, with
//! RFC 1929 username/password) and the HTTP proxy forms consoles offer in
//! their network settings.
//!
//! Parsers take whatever has arrived so far and say whether it is enough, so
//! the event loop can feed them partial reads without blocking on a client.

use base64::Engine as _;
use std::net::{Ipv4Addr, SocketAddrV4};

pub(crate) const SOCKS_VERSION: u8 = 5;
pub(crate) const METHOD_NONE: u8 = 0x00;
pub(crate) const METHOD_USER_PASS: u8 = 0x02;
pub(crate) const METHOD_UNACCEPTABLE: u8 = 0xff;
const USER_PASS_VERSION: u8 = 1;

pub(crate) const COMMAND_CONNECT: u8 = 1;
pub(crate) const COMMAND_UDP_ASSOCIATE: u8 = 3;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

/// Longest HTTP request head accepted before the first body byte.
const MAX_HTTP_HEAD: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reply {
    Succeeded = 0,
    GeneralFailure = 1,
    NotAllowed = 2,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    TtlExpired = 6,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    Ip(SocketAddrV4),
    Domain(String, u16),
    /// Named so it can be refused with the right reply; the session is IPv4.
    Ipv6,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Parse<T> {
    Incomplete,
    Done(T, usize),
    Invalid(&'static str),
}

pub(crate) fn parse_greeting(buffer: &[u8]) -> Parse<Vec<u8>> {
    let [version, count, ..] = buffer else {
        return Parse::Incomplete;
    };
    if *version != SOCKS_VERSION {
        return Parse::Invalid("not a SOCKS5 greeting");
    }
    let end = 2 + usize::from(*count);
    match buffer.get(2..end) {
        Some(methods) => Parse::Done(methods.to_vec(), end),
        None => Parse::Incomplete,
    }
}

pub(crate) fn parse_user_pass(buffer: &[u8]) -> Parse<(String, String)> {
    let [version, user_length, ..] = buffer else {
        return Parse::Incomplete;
    };
    if *version != USER_PASS_VERSION {
        return Parse::Invalid("unknown username/password version");
    }
    let user_end = 2 + usize::from(*user_length);
    let Some(&password_length) = buffer.get(user_end) else {
        return Parse::Incomplete;
    };
    let end = user_end + 1 + usize::from(password_length);
    if buffer.len() < end {
        return Parse::Incomplete;
    }
    let user = String::from_utf8_lossy(&buffer[2..user_end]).into_owned();
    let password = String::from_utf8_lossy(&buffer[user_end + 1..end]).into_owned();
    Parse::Done((user, password), end)
}

pub(crate) fn user_pass_reply(accepted: bool) -> [u8; 2] {
    [USER_PASS_VERSION, if accepted { 0 } else { 1 }]
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) command: u8,
    pub(crate) target: Target,
}

pub(crate) fn parse_request(buffer: &[u8]) -> Parse<Request> {
    let [version, command, _reserved, ..] = buffer else {
        return Parse::Incomplete;
    };
    if *version != SOCKS_VERSION {
        return Parse::Invalid("not a SOCKS5 request");
    }
    match parse_address(&buffer[3..]) {
        Parse::Done(target, used) => Parse::Done(
            Request {
                command: *command,
                target,
            },
            3 + used,
        ),
        Parse::Incomplete => Parse::Incomplete,
        Parse::Invalid(reason) => Parse::Invalid(reason),
    }
}

/// `ATYP | ADDR | PORT`, shared by requests and UDP datagram headers.
fn parse_address(buffer: &[u8]) -> Parse<Target> {
    let Some(&kind) = buffer.first() else {
        return Parse::Incomplete;
    };
    let port = |at: usize| u16::from_be_bytes([buffer[at], buffer[at + 1]]);
    match kind {
        ATYP_IPV4 if buffer.len() >= 7 => {
            let address = Ipv4Addr::new(buffer[1], buffer[2], buffer[3], buffer[4]);
            Parse::Done(Target::Ip(SocketAddrV4::new(address, port(5))), 7)
        }
        ATYP_DOMAIN if buffer.len() >= 2 => {
            let end = 2 + usize::from(buffer[1]);
            if buffer.len() < end + 2 {
                return Parse::Incomplete;
            }
            let name = String::from_utf8_lossy(&buffer[2..end]).into_owned();
            Parse::Done(domain_target(name, port(end)), end + 2)
        }
        ATYP_IPV6 if buffer.len() >= 19 => Parse::Done(Target::Ipv6, 19),
        ATYP_IPV4 | ATYP_DOMAIN | ATYP_IPV6 => Parse::Incomplete,
        _ => Parse::Invalid("unknown address type"),
    }
}

/// A "domain" that is really an address literal, which some clients send.
fn domain_target(name: String, port: u16) -> Target {
    match name.parse::<Ipv4Addr>() {
        Ok(address) => Target::Ip(SocketAddrV4::new(address, port)),
        Err(_) if name.contains(':') => Target::Ipv6,
        Err(_) => Target::Domain(name.trim_end_matches('.').to_ascii_lowercase(), port),
    }
}

pub(crate) fn reply(code: Reply, bound: SocketAddrV4) -> Vec<u8> {
    let mut reply = vec![SOCKS_VERSION, code as u8, 0, ATYP_IPV4];
    reply.extend_from_slice(&bound.ip().octets());
    reply.extend_from_slice(&bound.port().to_be_bytes());
    reply
}

/// Splits a client's UDP datagram into where it is going and what it carries.
/// Fragmented datagrams are refused, as RFC 1928 allows a server to do.
pub(crate) fn parse_udp_datagram(datagram: &[u8]) -> Option<(Target, &[u8])> {
    let [0, 0, 0, ..] = datagram else {
        return None;
    };
    match parse_address(&datagram[3..]) {
        Parse::Done(target, used) => Some((target, &datagram[3 + used..])),
        _ => None,
    }
}

pub(crate) fn udp_datagram(from: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(10 + payload.len());
    datagram.extend_from_slice(&[0, 0, 0, ATYP_IPV4]);
    datagram.extend_from_slice(&from.ip().octets());
    datagram.extend_from_slice(&from.port().to_be_bytes());
    datagram.extend_from_slice(payload);
    datagram
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HttpRequest {
    pub(crate) target: Target,
    /// `CONNECT` tunnels; anything else is forwarded as a plain request.
    pub(crate) tunnel: bool,
    pub(crate) credentials: Option<(String, String)>,
    /// For a forwarded request: the head to send upstream, in origin form and
    /// without the proxy's own headers.
    pub(crate) upstream_head: Vec<u8>,
}

pub(crate) fn parse_http_request(buffer: &[u8]) -> Parse<HttpRequest> {
    let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
        return if buffer.len() > MAX_HTTP_HEAD {
            Parse::Invalid("HTTP request head is too large")
        } else {
            Parse::Incomplete
        };
    };
    let Ok(head) = std::str::from_utf8(&buffer[..end]) else {
        return Parse::Invalid("HTTP request head is not text");
    };
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(uri), Some(version)) = (
        request_line.next(),
        request_line.next(),
        request_line.next(),
    ) else {
        return Parse::Invalid("malformed HTTP request line");
    };
    let headers = lines.collect::<Vec<_>>();
    let credentials = headers.iter().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
            return None;
        }
        let encoded = value.trim().strip_prefix("Basic ")?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?;
        let (user, password) = std::str::from_utf8(&decoded).ok()?.split_once(':')?;
        Some((user.to_owned(), password.to_owned()))
    });
    let consumed = end + 4;
    if method.eq_ignore_ascii_case("CONNECT") {
        let Some(target) = authority_target(uri, 443) else {
            return Parse::Invalid("CONNECT needs a host and port");
        };
        return Parse::Done(
            HttpRequest {
                target,
                tunnel: true,
                credentials,
                upstream_head: Vec::new(),
            },
            consumed,
        );
    }
    let Some(rest) = uri.strip_prefix("http://") else {
        return Parse::Invalid("a proxied request needs an absolute http:// URI");
    };
    let (authority, path) = match rest.find('/') {
        Some(slash) => (&rest[..slash], &rest[slash..]),
        None => (rest, "/"),
    };
    let Some(target) = authority_target(authority, 80) else {
        return Parse::Invalid("the request URI names no host");
    };
    // One request per upstream connection: a client reusing this connection
    // for another host would otherwise be sent to the first one.
    let mut upstream = format!("{method} {path} {version}\r\n");
    for line in headers {
        let name = line.split_once(':').map_or(line, |(name, _)| name).trim();
        if [
            "proxy-authorization",
            "proxy-connection",
            "connection",
            "keep-alive",
        ]
        .iter()
        .any(|hop| name.eq_ignore_ascii_case(hop))
        {
            continue;
        }
        upstream.push_str(line);
        upstream.push_str("\r\n");
    }
    upstream.push_str("Connection: close\r\n\r\n");
    Parse::Done(
        HttpRequest {
            target,
            tunnel: false,
            credentials,
            upstream_head: upstream.into_bytes(),
        },
        consumed,
    )
}

/// `host:port`, `[v6]:port` or a bare host, into a target.
fn authority_target(authority: &str, default_port: u16) -> Option<Target> {
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if authority.starts_with('[') {
        return Some(Target::Ipv6);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (authority, default_port),
    };
    (!host.is_empty()).then(|| domain_target(host.to_owned(), port))
}

pub(crate) const HTTP_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
pub(crate) const HTTP_AUTH_REQUIRED: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Basic realm=\"GamePath\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

pub(crate) fn http_failure(reply: Reply) -> &'static [u8] {
    match reply {
        Reply::TtlExpired | Reply::HostUnreachable => {
            b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        Reply::NotAllowed => {
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        Reply::AddressTypeNotSupported | Reply::CommandNotSupported => {
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        _ => b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_greeting_waits_for_every_method() {
        assert_eq!(parse_greeting(&[5, 2, 0]), Parse::Incomplete);
        assert_eq!(parse_greeting(&[5, 2, 0, 2, 9]), Parse::Done(vec![0, 2], 4));
        assert_eq!(
            parse_greeting(&[4, 1, 0]),
            Parse::Invalid("not a SOCKS5 greeting")
        );
    }

    #[test]
    fn credentials_are_read_whole() {
        let message = [1, 3, b'b', b'o', b'b', 2, b'p', b'w'];
        assert_eq!(parse_user_pass(&message[..6]), Parse::Incomplete);
        assert_eq!(
            parse_user_pass(&message),
            Parse::Done(("bob".into(), "pw".into()), 8)
        );
    }

    #[test]
    fn requests_name_ipv4_domain_and_ipv6_targets() {
        let ipv4 = [5, 1, 0, 1, 1, 2, 3, 4, 0x01, 0xbb];
        assert_eq!(
            parse_request(&ipv4),
            Parse::Done(
                Request {
                    command: COMMAND_CONNECT,
                    target: Target::Ip("1.2.3.4:443".parse().unwrap()),
                },
                10
            )
        );
        let mut domain = vec![5, 3, 0, 3, 11];
        domain.extend_from_slice(b"Example.COM");
        domain.extend_from_slice(&[0, 53]);
        assert_eq!(
            parse_request(&domain),
            Parse::Done(
                Request {
                    command: COMMAND_UDP_ASSOCIATE,
                    target: Target::Domain("example.com".into(), 53),
                },
                domain.len()
            )
        );
        assert_eq!(parse_request(&domain[..8]), Parse::Incomplete);
        let mut ipv6 = vec![5, 1, 0, 4];
        ipv6.extend_from_slice(&[0; 18]);
        assert!(matches!(
            parse_request(&ipv6),
            Parse::Done(
                Request {
                    target: Target::Ipv6,
                    ..
                },
                22
            )
        ));
    }

    #[test]
    fn an_address_literal_sent_as_a_domain_is_an_address() {
        let mut request = vec![5, 1, 0, 3, 7];
        request.extend_from_slice(b"8.8.8.8");
        request.extend_from_slice(&[0, 53]);
        let Parse::Done(request, _) = parse_request(&request) else {
            panic!("complete request");
        };
        assert_eq!(request.target, Target::Ip("8.8.8.8:53".parse().unwrap()));
    }

    #[test]
    fn udp_datagrams_round_trip_and_fragments_are_refused() {
        let from: SocketAddrV4 = "9.9.9.9:3074".parse().unwrap();
        let datagram = udp_datagram(from, b"game");
        assert_eq!(
            parse_udp_datagram(&datagram),
            Some((Target::Ip(from), &b"game"[..]))
        );
        let mut fragment = datagram.clone();
        fragment[2] = 1;
        assert_eq!(parse_udp_datagram(&fragment), None);
    }

    #[test]
    fn http_connect_reads_the_authority_and_basic_credentials() {
        let request = b"CONNECT store.example:443 HTTP/1.1\r\nHost: store.example:443\r\n\
Proxy-Authorization: Basic Ym9iOnB3\r\n\r\nextra";
        let Parse::Done(parsed, used) = parse_http_request(request) else {
            panic!("complete head");
        };
        assert_eq!(used, request.len() - 5);
        assert!(parsed.tunnel);
        assert_eq!(parsed.target, Target::Domain("store.example".into(), 443));
        assert_eq!(parsed.credentials, Some(("bob".into(), "pw".into())));
    }

    #[test]
    fn a_forwarded_request_is_rewritten_to_origin_form_without_proxy_headers() {
        let request = b"GET http://1.2.3.4:8080/a?b HTTP/1.1\r\nHost: 1.2.3.4:8080\r\n\
Proxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n";
        let Parse::Done(parsed, _) = parse_http_request(request) else {
            panic!("complete head");
        };
        assert!(!parsed.tunnel);
        assert_eq!(parsed.target, Target::Ip("1.2.3.4:8080".parse().unwrap()));
        assert_eq!(
            String::from_utf8(parsed.upstream_head).unwrap(),
            "GET /a?b HTTP/1.1\r\nHost: 1.2.3.4:8080\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn an_unfinished_http_head_waits_and_an_endless_one_is_refused() {
        assert_eq!(
            parse_http_request(b"CONNECT a:1 HTTP/1.1\r\n"),
            Parse::Incomplete
        );
        assert_eq!(
            parse_http_request(&vec![b'a'; MAX_HTTP_HEAD + 1]),
            Parse::Invalid("HTTP request head is too large")
        );
    }
}

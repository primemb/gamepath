//! The client side of a SOCKS5 handshake (RFC 1928, RFC 1929), as a state
//! machine fed bytes as they arrive. It owns no socket, so the event loop can
//! drive hundreds of them on non-blocking streams, and tests drive it with
//! plain byte slices.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

const VERSION: u8 = 5;
const METHOD_NONE: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_UNACCEPTABLE: u8 = 0xff;
const AUTH_VERSION: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Connect = 0x01,
    UdpAssociate = 0x03,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Method,
    Auth,
    Reply,
    Done,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Write these bytes, then wait for more.
    Send(Vec<u8>),
    /// Nothing to do until more arrives.
    Wait,
    /// The proxy agreed. `bound` is its reply address; `leftover` is data
    /// that arrived behind the reply and belongs to the connection.
    Done {
        bound: SocketAddr,
        leftover: Vec<u8>,
    },
}

pub(crate) struct Handshake {
    stage: Stage,
    command: Command,
    target: SocketAddrV4,
    credentials: Option<(String, String)>,
    input: Vec<u8>,
}

impl Handshake {
    /// Starts a handshake; the returned bytes are the greeting to send first.
    pub(crate) fn start(
        command: Command,
        target: SocketAddrV4,
        credentials: Option<(String, String)>,
    ) -> (Self, Vec<u8>) {
        let greeting = if credentials.is_some() {
            vec![VERSION, 2, METHOD_NONE, METHOD_USERPASS]
        } else {
            vec![VERSION, 1, METHOD_NONE]
        };
        let handshake = Self {
            stage: Stage::Method,
            command,
            target,
            credentials,
            input: Vec::new(),
        };
        (handshake, greeting)
    }

    pub(crate) fn receive(&mut self, data: &[u8]) -> Result<Step, String> {
        self.input.extend_from_slice(data);
        match self.stage {
            Stage::Method => self.method(),
            Stage::Auth => self.auth(),
            Stage::Reply => self.reply(),
            Stage::Done => Err("the SOCKS5 handshake already finished".into()),
        }
    }

    fn method(&mut self) -> Result<Step, String> {
        let Some(&[version, method]) = self.input.get(..2) else {
            return Ok(Step::Wait);
        };
        if version != VERSION {
            return Err(format!(
                "the proxy is not SOCKS5 (it answered version {version})"
            ));
        }
        self.input.drain(..2);
        match method {
            METHOD_NONE => self.request(),
            METHOD_USERPASS => {
                let Some((username, password)) = &self.credentials else {
                    return Err("the SOCKS5 proxy requires a username and password".into());
                };
                let mut auth = vec![AUTH_VERSION, username.len() as u8];
                auth.extend_from_slice(username.as_bytes());
                auth.push(password.len() as u8);
                auth.extend_from_slice(password.as_bytes());
                self.stage = Stage::Auth;
                Ok(Step::Send(auth))
            }
            METHOD_UNACCEPTABLE => {
                Err("the SOCKS5 proxy accepted none of the login methods offered".into())
            }
            other => Err(format!(
                "the SOCKS5 proxy asked for login method {other}, which GamePath does not support"
            )),
        }
    }

    fn auth(&mut self) -> Result<Step, String> {
        let Some(&[_, status]) = self.input.get(..2) else {
            return Ok(Step::Wait);
        };
        self.input.drain(..2);
        if status != 0 {
            return Err("the SOCKS5 proxy rejected the username and password".into());
        }
        self.request()
    }

    fn request(&mut self) -> Result<Step, String> {
        let mut request = vec![VERSION, self.command as u8, 0, ATYP_IPV4];
        request.extend_from_slice(&self.target.ip().octets());
        request.extend_from_slice(&self.target.port().to_be_bytes());
        self.stage = Stage::Reply;
        // A proxy that answers fast may already have put its reply behind
        // the method byte; it is parsed on the next receive.
        Ok(Step::Send(request))
    }

    fn reply(&mut self) -> Result<Step, String> {
        let Some(&[version, code, _, address_type]) = self.input.get(..4) else {
            return Ok(Step::Wait);
        };
        if version != VERSION {
            return Err(format!(
                "the proxy is not SOCKS5 (it answered version {version})"
            ));
        }
        if code != 0 {
            return Err(reply_error(code));
        }
        let address_length = match address_type {
            ATYP_IPV4 => 4,
            ATYP_IPV6 => 16,
            ATYP_DOMAIN => match self.input.get(4) {
                Some(length) => 1 + usize::from(*length),
                None => return Ok(Step::Wait),
            },
            other => {
                return Err(format!(
                    "the SOCKS5 proxy replied with address type {other}"
                ));
            }
        };
        let total = 4 + address_length + 2;
        if self.input.len() < total {
            return Ok(Step::Wait);
        }
        let port = u16::from_be_bytes([self.input[total - 2], self.input[total - 1]]);
        let address = &self.input[4..4 + address_length];
        let ip = match address_type {
            ATYP_IPV4 => IpAddr::V4(Ipv4Addr::new(
                address[0], address[1], address[2], address[3],
            )),
            ATYP_IPV6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(address).unwrap())),
            // A name cannot be dialled without a lookup; callers only use the
            // port of a bound address, so the unspecified address stands in.
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        let leftover = self.input.split_off(total);
        self.input.clear();
        self.stage = Stage::Done;
        Ok(Step::Done {
            bound: SocketAddr::new(ip, port),
            leftover,
        })
    }
}

/// RFC 1928's reply codes, in words a user can act on.
pub(crate) fn reply_error(code: u8) -> String {
    let reason = match code {
        1 => "general failure",
        2 => "not allowed by its rules",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "an unknown error",
    };
    format!("the SOCKS5 proxy refused the request: {reason} (code {code})")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443);

    fn connect_request() -> Vec<u8> {
        vec![5, 1, 0, 1, 93, 184, 216, 34, 0x01, 0xbb]
    }

    #[test]
    fn a_proxy_without_login_goes_straight_to_the_request() {
        let (mut handshake, greeting) = Handshake::start(Command::Connect, TARGET, None);
        assert_eq!(greeting, [5, 1, 0]);
        assert_eq!(
            handshake.receive(&[5, 0]).unwrap(),
            Step::Send(connect_request())
        );
        assert_eq!(handshake.receive(&[5, 0, 0, 1, 10, 0]).unwrap(), Step::Wait);
        assert_eq!(
            handshake.receive(&[0, 1, 0x1f, 0x90, b'h', b'i']).unwrap(),
            Step::Done {
                bound: "10.0.0.1:8080".parse().unwrap(),
                leftover: b"hi".to_vec(),
            }
        );
    }

    #[test]
    fn a_login_is_sent_only_when_the_proxy_asks_for_it() {
        let credentials = Some(("user".to_owned(), "pass".to_owned()));
        let (mut handshake, greeting) = Handshake::start(Command::Connect, TARGET, credentials);
        assert_eq!(greeting, [5, 2, 0, 2]);
        assert_eq!(
            handshake.receive(&[5, 2]).unwrap(),
            Step::Send(b"\x01\x04user\x04pass".to_vec())
        );
        assert_eq!(
            handshake.receive(&[1, 0]).unwrap(),
            Step::Send(connect_request())
        );
        let mut rejected =
            Handshake::start(Command::Connect, TARGET, Some(("u".into(), "p".into()))).0;
        rejected.receive(&[5, 2]).unwrap();
        assert!(rejected.receive(&[1, 1]).unwrap_err().contains("rejected"));
    }

    #[test]
    fn a_proxy_that_wants_a_login_none_was_given_is_explained() {
        let (mut handshake, _) = Handshake::start(Command::Connect, TARGET, None);
        assert!(
            handshake
                .receive(&[5, 2])
                .unwrap_err()
                .contains("username and password")
        );
        let (mut handshake, _) = Handshake::start(Command::Connect, TARGET, None);
        assert!(
            handshake
                .receive(&[5, 0xff])
                .unwrap_err()
                .contains("none of the login")
        );
        let (mut handshake, _) = Handshake::start(Command::Connect, TARGET, None);
        assert!(
            handshake
                .receive(&[4, 0])
                .unwrap_err()
                .contains("not SOCKS5")
        );
    }

    #[test]
    fn a_refused_request_says_why() {
        let (mut handshake, _) = Handshake::start(Command::Connect, TARGET, None);
        handshake.receive(&[5, 0]).unwrap();
        let error = handshake
            .receive(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
            .unwrap_err();
        assert!(error.contains("connection refused"), "{error}");
    }

    #[test]
    fn a_udp_association_reports_where_to_send_datagrams() {
        let (mut handshake, _) = Handshake::start(
            Command::UdpAssociate,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            None,
        );
        assert_eq!(
            handshake.receive(&[5, 0]).unwrap(),
            Step::Send(vec![5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        );
        // A domain-name reply and a reply split across reads both parse.
        assert_eq!(
            handshake.receive(&[5, 0, 0, 3, 5, b'p', b'r']).unwrap(),
            Step::Wait
        );
        assert_eq!(
            handshake.receive(&[b'o', b'x', b'y', 0x10, 0x00]).unwrap(),
            Step::Done {
                bound: "0.0.0.0:4096".parse().unwrap(),
                leftover: Vec::new(),
            }
        );
    }
}

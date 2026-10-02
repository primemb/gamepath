//! `--verify-x509-name`: the server certificate's subject, checked the way the
//! reference client checks it.
//!
//! Only the leaf certificate's subject is compared. `name` and `name-prefix`
//! use the last common name, as OpenVPN's `extract_x509_field_ssl` does, and
//! `subject` compares the whole name in OpenVPN's `C=.., ST=.., CN=..` form.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerNameCheck {
    Subject(String),
    Name(String),
    NamePrefix(String),
}

impl ServerNameCheck {
    pub fn parse(arguments: &[String]) -> Result<Self, String> {
        let name = arguments
            .first()
            .filter(|name| !name.is_empty())
            .ok_or("`verify-x509-name` needs the name the server's certificate must carry")?
            .clone();
        match arguments.get(1).map(String::as_str).unwrap_or("subject") {
            "subject" => Ok(Self::Subject(name)),
            "name" => Ok(Self::Name(name)),
            "name-prefix" => Ok(Self::NamePrefix(name)),
            other => Err(format!(
                "`verify-x509-name` type `{other}` is not one of subject, name or name-prefix"
            )),
        }
    }

    pub fn matches(&self, certificate: &[u8]) -> bool {
        let Some(subject) = subject(certificate) else {
            return false;
        };
        match self {
            Self::Subject(expected) => {
                format_subject(&subject).is_some_and(|actual| actual == *expected)
            }
            Self::Name(expected) => last_common_name(&subject) == Some(expected.as_str()),
            Self::NamePrefix(prefix) => {
                last_common_name(&subject).is_some_and(|name| name.starts_with(prefix.as_str()))
            }
        }
    }
}

const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

/// One relative distinguished name: its attributes, in certificate order.
type Rdn = Vec<(Vec<u8>, String)>;

fn last_common_name(subject: &[Rdn]) -> Option<&str> {
    subject
        .iter()
        .flatten()
        .filter(|(oid, _)| oid == COMMON_NAME)
        .map(|(_, value)| value.as_str())
        .next_back()
}

/// OpenVPN prints the subject with `XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN`:
/// short names, `, ` between names and ` + ` inside a multi-valued one.
fn format_subject(subject: &[Rdn]) -> Option<String> {
    let mut names = Vec::with_capacity(subject.len());
    for rdn in subject {
        let attributes = rdn
            .iter()
            .map(|(oid, value)| short_name(oid).map(|name| format!("{name}={value}")))
            .collect::<Option<Vec<_>>>()?;
        names.push(attributes.join(" + "));
    }
    Some(names.join(", "))
}

fn short_name(oid: &[u8]) -> Option<&'static str> {
    Some(match oid {
        [0x55, 0x04, 0x03] => "CN",
        [0x55, 0x04, 0x04] => "SN",
        [0x55, 0x04, 0x05] => "serialNumber",
        [0x55, 0x04, 0x06] => "C",
        [0x55, 0x04, 0x07] => "L",
        [0x55, 0x04, 0x08] => "ST",
        [0x55, 0x04, 0x09] => "street",
        [0x55, 0x04, 0x0a] => "O",
        [0x55, 0x04, 0x0b] => "OU",
        [0x55, 0x04, 0x0c] => "title",
        [0x55, 0x04, 0x29] => "name",
        [0x55, 0x04, 0x2a] => "GN",
        [0x55, 0x04, 0x2b] => "initials",
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "emailAddress",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01] => "UID",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "DC",
        _ => return None,
    })
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const OBJECT_IDENTIFIER: u8 = 0x06;
const EXPLICIT_VERSION: u8 = 0xa0;

/// The subject of a DER certificate: Certificate → TBSCertificate → the field
/// after version, serial, signature, issuer and validity (RFC 5280 §4.1).
fn subject(certificate: &[u8]) -> Option<Vec<Rdn>> {
    let (tag, certificate, _) = read(certificate)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, mut fields, _) = read(certificate)?;
    if tag != SEQUENCE {
        return None;
    }
    if fields.first() == Some(&EXPLICIT_VERSION) {
        fields = read(fields)?.2;
    }
    for _ in ["serial", "signature", "issuer", "validity"] {
        fields = read(fields)?.2;
    }
    let (tag, mut name, _) = read(fields)?;
    if tag != SEQUENCE {
        return None;
    }
    let mut rdns = Vec::new();
    while !name.is_empty() {
        let (tag, mut set, rest) = read(name)?;
        if tag != SET {
            return None;
        }
        let mut rdn = Vec::new();
        while !set.is_empty() {
            let (tag, attribute, next) = read(set)?;
            let (oid_tag, oid, value) = read(attribute)?;
            if tag != SEQUENCE || oid_tag != OBJECT_IDENTIFIER {
                return None;
            }
            let (string_tag, value, _) = read(value)?;
            rdn.push((oid.to_vec(), decode_string(string_tag, value)?));
            set = next;
        }
        rdns.push(rdn);
        name = rest;
    }
    Some(rdns)
}

fn decode_string(tag: u8, value: &[u8]) -> Option<String> {
    match tag {
        // UTF8String, PrintableString, IA5String
        0x0c | 0x13 | 0x16 => String::from_utf8(value.to_vec()).ok(),
        // TeletexString, read as Latin-1 as OpenSSL does
        0x14 => Some(value.iter().copied().map(char::from).collect()),
        // BMPString
        0x1e if value.len() % 2 == 0 => char::decode_utf16(
            value
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]])),
        )
        .collect::<Result<String, _>>()
        .ok(),
        _ => None,
    }
}

/// One DER element: its tag, its contents and whatever follows it.
fn read(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, input) = input.split_first()?;
    let (&first, mut input) = input.split_first()?;
    let length = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || input.len() < count {
            return None;
        }
        let (bytes, rest) = input.split_at(count);
        input = rest;
        bytes
            .iter()
            .fold(0_usize, |length, &byte| (length << 8) | usize::from(byte))
    };
    (input.len() >= length).then(|| {
        let (contents, rest) = input.split_at(length);
        (tag, contents, rest)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if contents.len() < 0x80 {
            out.push(contents.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(contents);
        out
    }

    fn attribute(oid: &[u8], tag: u8, value: &[u8]) -> Vec<u8> {
        tlv(
            SEQUENCE,
            &[tlv(OBJECT_IDENTIFIER, oid), tlv(tag, value)].concat(),
        )
    }

    fn certificate(subject: &[Vec<Vec<u8>>]) -> Vec<u8> {
        let name = tlv(
            SEQUENCE,
            &subject
                .iter()
                .map(|rdn| tlv(SET, &rdn.concat()))
                .collect::<Vec<_>>()
                .concat(),
        );
        let tbs = tlv(
            SEQUENCE,
            &[
                tlv(EXPLICIT_VERSION, &tlv(0x02, &[2])),
                tlv(0x02, &[1]),
                tlv(SEQUENCE, &tlv(OBJECT_IDENTIFIER, &[0x2a, 0x86, 0x48])),
                tlv(SEQUENCE, &[]),
                tlv(SEQUENCE, &[]),
                name,
                tlv(SEQUENCE, &[0; 200]),
            ]
            .concat(),
        );
        tlv(
            SEQUENCE,
            &[tbs, tlv(SEQUENCE, &[]), tlv(0x03, &[0])].concat(),
        )
    }

    fn windscribe() -> Vec<u8> {
        certificate(&[
            vec![attribute(&[0x55, 0x04, 0x06], 0x13, b"CA")],
            vec![attribute(&[0x55, 0x04, 0x0a], 0x0c, b"Windscribe Limited")],
            vec![attribute(COMMON_NAME, 0x0c, b"arn-476.windscribe.com")],
        ])
    }

    fn check(arguments: &[&str]) -> ServerNameCheck {
        ServerNameCheck::parse(
            &arguments
                .iter()
                .map(|&argument| argument.to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn name_compares_the_common_name_exactly() {
        assert!(check(&["arn-476.windscribe.com", "name"]).matches(&windscribe()));
        assert!(!check(&["arn-477.windscribe.com", "name"]).matches(&windscribe()));
        assert!(!check(&["arn-476.windscribe.co", "name"]).matches(&windscribe()));
    }

    #[test]
    fn name_prefix_compares_the_start_of_the_common_name() {
        assert!(check(&["arn-", "name-prefix"]).matches(&windscribe()));
        assert!(!check(&["fra-", "name-prefix"]).matches(&windscribe()));
    }

    #[test]
    fn subject_is_the_default_and_uses_openvpns_format() {
        assert_eq!(
            check(&["C=CA, O=Windscribe Limited, CN=arn-476.windscribe.com"]),
            ServerNameCheck::Subject(
                "C=CA, O=Windscribe Limited, CN=arn-476.windscribe.com".into()
            )
        );
        assert!(
            check(&["C=CA, O=Windscribe Limited, CN=arn-476.windscribe.com"])
                .matches(&windscribe())
        );
        assert!(!check(&["CN=arn-476.windscribe.com"]).matches(&windscribe()));
    }

    #[test]
    fn the_last_common_name_is_the_one_compared() {
        let certificate = certificate(&[
            vec![attribute(COMMON_NAME, 0x0c, b"first")],
            vec![attribute(COMMON_NAME, 0x13, b"server")],
        ]);
        assert!(check(&["server", "name"]).matches(&certificate));
        assert!(!check(&["first", "name"]).matches(&certificate));
    }

    #[test]
    fn a_multi_valued_name_and_a_bmp_string_are_read() {
        let certificate = certificate(&[vec![
            attribute(&[0x55, 0x04, 0x0b], 0x1e, &[0, b'o', 0, b'p', 0, b's']),
            attribute(COMMON_NAME, 0x0c, b"vpn"),
        ]]);
        assert!(check(&["OU=ops + CN=vpn"]).matches(&certificate));
    }

    #[test]
    fn a_malformed_certificate_never_matches() {
        let valid = windscribe();
        let name = check(&["arn-476.windscribe.com", "name"]);
        for length in 0..valid.len() / 2 {
            assert!(!name.matches(&valid[..length]));
        }
        assert!(!name.matches(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]));
    }

    #[test]
    fn an_unknown_type_or_a_missing_name_is_refused() {
        assert!(ServerNameCheck::parse(&[]).is_err());
        assert!(ServerNameCheck::parse(&["x".into(), "cn".into()]).is_err());
    }
}

use crate::dns::{self, ResolverVerdict};

pub(super) struct DnsProbe {
    message: Vec<u8>,
    received: Vec<u8>,
    id: u16,
}

impl DnsProbe {
    pub(super) fn new() -> Self {
        let id = rand::random();
        // A fresh question avoids reusing the proxy's cached success after its
        // upstream stops working. A valid NXDOMAIN still proves DNS answered.
        let name = format!("gp-{:016x}.example.com", rand::random::<u64>());
        let message = dns::query(id, &name).expect("the probe name fits DNS limits");
        Self {
            message,
            received: Vec::new(),
            id,
        }
    }

    pub(super) fn framed(&self) -> Vec<u8> {
        let mut frame = (self.message.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&self.message);
        frame
    }

    pub(super) fn receive(&mut self, bytes: &[u8]) -> Option<bool> {
        if self.received.len() + bytes.len() > usize::from(u16::MAX) + 2 {
            return Some(false);
        }
        self.received.extend_from_slice(bytes);
        let prefix = self.received.get(..2)?;
        let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        if length < 12 {
            return Some(false);
        }
        let response = self.received.get(2..2 + length)?;
        Some(
            matches!(
                dns::verdict(response, self.id),
                ResolverVerdict::Answered | ResolverVerdict::Refused { rcode: 3 }
            ) && response[2] & 0x7a == 0
                && response.get(4..6) == Some(&[0, 1])
                && response.get(12..self.message.len()) == self.message.get(12..),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_complete_matching_dns_answer_proves_the_proxy_works() {
        for rcode in [0, 3, 2, 5] {
            let mut probe = DnsProbe::new();
            let mut frame = probe.framed();
            frame[4] |= 0x80;
            frame[5] = rcode;
            assert_eq!(probe.receive(&frame[..1]), None);
            assert_eq!(probe.receive(&frame[1..8]), None);
            assert_eq!(probe.receive(&frame[8..]), Some(matches!(rcode, 0 | 3)));
        }
        let mut probe = DnsProbe::new();
        assert_eq!(probe.receive(&probe.framed()), Some(false));
        let mut probe = DnsProbe::new();
        let mut frame = probe.framed();
        frame[4] |= 0x80;
        frame[2] ^= 1;
        assert_eq!(probe.receive(&frame), Some(false));
        let mut probe = DnsProbe::new();
        let mut frame = probe.framed();
        frame[4] |= 0x80;
        frame[15] ^= 1;
        assert_eq!(probe.receive(&frame), Some(false));
        let mut probe = DnsProbe::new();
        assert_eq!(probe.receive(&[0, 1]), Some(false));
        let mut probe = DnsProbe::new();
        assert_eq!(probe.receive(&vec![0; 65_538]), Some(false));
    }
}

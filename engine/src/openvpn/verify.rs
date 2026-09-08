//! Checking an OpenVPN server's certificate.
//!
//! OpenVPN does not authenticate a server by hostname. A configuration carries
//! the certificate authority that signed the server, and that -- plus the
//! server-authentication marking the reference client's `remote-cert-tls
//! server` insists on -- is the whole check. Servers are routinely reached by
//! bare IP, and their certificates routinely carry a name like `SERVER` that
//! matches nothing, so the usual hostname verification would reject working
//! configurations.
//!
//! What this deliberately does not do is skip verification. The chain still has
//! to reach the configuration's own CA, still has to be inside its validity
//! dates, and the signature over the handshake still has to check out.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use std::sync::Arc;

#[derive(Debug)]
pub struct EmbeddedCaVerifier {
    roots: Arc<RootCertStore>,
    provider: Arc<CryptoProvider>,
}

impl EmbeddedCaVerifier {
    pub fn new(ca: &[Vec<u8>], provider: Arc<CryptoProvider>) -> Result<Self, String> {
        let mut roots = RootCertStore::empty();
        for certificate in ca {
            roots
                .add(CertificateDer::from(certificate.clone()))
                .map_err(|error| {
                    format!("the `<ca>` block is not a usable certificate authority: {error}")
                })?;
        }
        if roots.is_empty() {
            return Err("the `<ca>` block did not yield a certificate authority".into());
        }
        Ok(Self {
            roots: Arc::new(roots),
            provider,
        })
    }
}

impl ServerCertVerifier for EmbeddedCaVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let certificate = rustls::server::ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &certificate,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_with_no_certificate_authority_is_refused() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        assert!(EmbeddedCaVerifier::new(&[], provider).is_err());
    }

    #[test]
    fn something_that_is_not_a_certificate_is_refused() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let error = EmbeddedCaVerifier::new(&[vec![1, 2, 3, 4]], provider).unwrap_err();
        assert!(error.contains("certificate authority"), "{error}");
    }
}

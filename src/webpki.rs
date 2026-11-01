#[cfg(not(any(
    feature = "p256",
    feature = "p384",
    feature = "ed25519",
    feature = "rsa"
)))]
compile_error!(
    "the `webpki` feature needs at least one signature algorithm feature: `p256`, `p384`, `ed25519` or `rsa`"
);

use crate::TlsError;
use crate::config::{Certificate, TlsCipherSuite, TlsClock, TlsVerifier};
use crate::crypto::{TlsHash, certificate_verify_message};
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::handshake::{
    certificate::{
        CertificateEntryRef, CertificateRef as ServerCertificate, MAX_CERTIFICATE_ENTRIES,
    },
    certificate_verify::CertificateVerifyRef,
};
use core::marker::PhantomData;
use core::time::Duration;
#[cfg(feature = "defmt")]
use defmt::Debug2Format;
use pki_types::{ServerName, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer, UnixTime};

pub use pki_types::{CertificateDer, TrustAnchor};

mod algorithms;

/// Verifies the server's certificate chain with rustls-webpki.
///
/// Signatures are checked through embassy-crypto, for the algorithms that the `p256`,
/// `p384` and `ed25519` features enable, and through the `rsa` crate with the `rsa` feature.
/// The server's first certificate is its own, and the rest are intermediates in any order.
/// rustls-webpki builds a path through at most six intermediates to one trusted root:
/// the certificate given to [`new`](Self::new), or any of the anchors given to
/// [`with_trust_anchors`](Self::with_trust_anchors).
///
/// The verifier keeps a copy of the server certificate's public key (its
/// `SubjectPublicKeyInfo`) until it checks the `CertificateVerify` signature, so `CERT_SIZE`
/// must hold that key: 91 bytes for P-256, 120 for P-384, 294 for RSA-2048 and 550 for
/// RSA-4096. The certificates are not copied. A larger key fails with
/// [`TlsError::OutOfMemory`] after the chain has been verified.
pub struct CertVerifier<'a, CipherSuite, Clock, const CERT_SIZE: usize>
where
    Clock: TlsClock,
    CipherSuite: TlsCipherSuite,
{
    roots: Roots<'a>,
    host: Option<heapless::String<64>>,
    certificate_transcript: Option<CipherSuite::Hash>,
    public_key: Option<heapless::Vec<u8, CERT_SIZE>>,
    _clock: PhantomData<Clock>,
}

/// The roots a chain may end at.
enum Roots<'a> {
    /// One root certificate, read as a trust anchor for each chain.
    Certificate(Certificate<&'a [u8]>),
    /// Any of these anchors.
    Anchors(&'a [TrustAnchor<'a>]),
}

impl<'a, CipherSuite, Clock, const CERT_SIZE: usize> CertVerifier<'a, CipherSuite, Clock, CERT_SIZE>
where
    Clock: TlsClock,
    CipherSuite: TlsCipherSuite,
{
    /// A verifier that trusts one root certificate, `ca`.
    #[must_use]
    pub fn new(ca: Certificate<&'a [u8]>) -> Self {
        Self::with_roots(Roots::Certificate(ca))
    }

    /// A verifier that trusts any of `anchors`, as a set of public roots does.
    ///
    /// [`trust_anchor`] reads an anchor from a DER root certificate without copying it. An
    /// empty set trusts nothing.
    #[must_use]
    pub fn with_trust_anchors(anchors: &'a [TrustAnchor<'a>]) -> Self {
        Self::with_roots(Roots::Anchors(anchors))
    }

    fn with_roots(roots: Roots<'a>) -> Self {
        Self {
            roots,
            host: None,
            certificate_transcript: None,
            public_key: None,
            _clock: PhantomData,
        }
    }
}

/// The trust anchor in `certificate`, a DER root certificate, borrowing its subject and key.
///
/// The certificate is taken as trusted: its signature, its dates and its extensions other than
/// name constraints are not checked, as for any root. `CertificateDer::from_slice` is `const`, so
/// a set of built-in roots can be a `static`.
pub fn trust_anchor<'a>(certificate: &'a CertificateDer<'a>) -> Result<TrustAnchor<'a>, TlsError> {
    webpki::anchor_from_trusted_cert(certificate).map_err(|e| refused(&e, TlsError::DecodeError))
}

impl<CipherSuite, Clock, const CERT_SIZE: usize> TlsVerifier<CipherSuite>
    for CertVerifier<'_, CipherSuite, Clock, CERT_SIZE>
where
    CipherSuite: TlsCipherSuite,
    Clock: TlsClock,
{
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), TlsError> {
        // A name rustls-webpki cannot match is refused here, not as a bad certificate later.
        ServerName::try_from(hostname).map_err(|_| TlsError::InvalidCertificate)?;
        self.host.replace(
            heapless::String::try_from(hostname).map_err(|_| TlsError::InsufficientSpace)?,
        );
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &CipherSuite::Hash,
        cert: ServerCertificate,
    ) -> Result<(), TlsError> {
        let Some(host) = self.host.as_deref() else {
            warn!("No server name is set, so the certificate is refused");
            return Err(TlsError::MissingServerName);
        };
        let now = if let Some(now) = Clock::now() {
            now
        } else {
            warn!("No time provided, so the certificate dates are checked at the clock's floor");
            latest_not_before(&cert)?.max(Clock::floor())
        };
        match &self.roots {
            Roots::Certificate(Certificate::X509(ca)) => {
                let ca = CertificateDer::from(*ca);
                let anchor = trust_anchor(&ca)?;
                verify_certificate(host, core::slice::from_ref(&anchor), &cert, now)?;
            }
            Roots::Certificate(_) => return Err(TlsError::DecodeError),
            Roots::Anchors(anchors) => verify_certificate(host, anchors, &cert, now)?,
        }
        let leaf = end_entity(&cert)?;
        let key = subject_public_key_info(&leaf).map_err(|_| TlsError::DecodeError)?;
        // Copied in place, so no second copy of `CERT_SIZE` bytes sits on the stack.
        let public_key = self.public_key.insert(heapless::Vec::new());
        public_key
            .extend_from_slice(key)
            .map_err(|_| TlsError::OutOfMemory)?;
        self.certificate_transcript.replace(transcript.clone());
        Ok(())
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), TlsError> {
        let handshake_hash = unwrap!(self.certificate_transcript.take());
        let msg = certificate_verify_message(
            b"TLS 1.3, server CertificateVerify\x00",
            handshake_hash.finalize().as_ref(),
        )?;

        let public_key = SubjectPublicKeyInfoDer::from(&unwrap!(self.public_key.as_ref())[..]);
        verify_signature(&msg[..], &public_key, &verify)
    }
}

/// The algorithm for a `CertificateVerify` signed with `scheme`.
///
/// RSA-PKCS#1 is refused: RFC 9846, section 4.3.3, defines the `rsa_pkcs1` schemes for
/// signatures in certificates only, not for `CertificateVerify`, even when the client offers them.
fn algorithm(
    scheme: SignatureScheme,
) -> Result<&'static dyn SignatureVerificationAlgorithm, TlsError> {
    match scheme {
        #[cfg(feature = "p256")]
        SignatureScheme::EcdsaSecp256r1Sha256 => Ok(&algorithms::ECDSA_P256_SHA256),
        #[cfg(feature = "p384")]
        SignatureScheme::EcdsaSecp384r1Sha384 => Ok(&algorithms::ECDSA_P384_SHA384),
        #[cfg(feature = "ed25519")]
        SignatureScheme::Ed25519 => Ok(&algorithms::ED25519),
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha256 => Ok(&algorithms::RSA_PSS_SHA256),
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha384 => Ok(&algorithms::RSA_PSS_SHA384),
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha512 => Ok(&algorithms::RSA_PSS_SHA512),
        _ => Err(TlsError::InvalidSignatureScheme),
    }
}

/// Logs why rustls-webpki refused a certificate or a signature, and returns `error` as `mapped`.
fn refused(error: &webpki::Error, mapped: TlsError) -> TlsError {
    #[cfg(feature = "defmt")]
    warn!("rustls-webpki refused: {:?}", Debug2Format(error));
    #[cfg(not(feature = "defmt"))]
    warn!("rustls-webpki refused: {:?}", error);
    mapped
}

/// The latest `notBefore` of the certificates in `certificate`, in seconds since the Unix epoch.
///
/// A certificate whose dates cannot be read fails the chain.
fn latest_not_before(certificate: &ServerCertificate) -> Result<u64, TlsError> {
    let mut latest = None;
    for entry in &certificate.entries {
        let CertificateEntryRef::X509(der) = entry else {
            return Err(TlsError::DecodeError);
        };
        let not_before = not_before(der).map_err(|_| TlsError::DecodeError)?;
        latest = latest.max(Some(not_before));
    }
    latest.ok_or(TlsError::DecodeError)
}

/// Reads the `tbsCertificate` of a DER certificate with `read`, which starts at `serialNumber`
/// (RFC 5280, section 4.1) and need not read to the end.
///
/// rustls-webpki keeps a certificate's fields private, so the dates and the public key are read
/// here.
fn read_tbs<'a, T>(
    certificate: &'a [u8],
    read: impl FnOnce(&mut der::SliceReader<'a>) -> der::Result<T>,
) -> der::Result<T> {
    use der::{Reader, SliceReader, Tag, TagNumber};

    let skip_rest = |reader: &mut SliceReader<'a>| -> der::Result<()> {
        while !reader.is_finished() {
            reader.tlv_bytes()?;
        }
        Ok(())
    };
    let mut reader = SliceReader::new(certificate)?;
    reader.sequence(|certificate| -> der::Result<T> {
        let value = certificate.sequence(|tbs| -> der::Result<T> {
            let version = Tag::ContextSpecific {
                constructed: true,
                number: TagNumber(0),
            };
            if Tag::peek(tbs)? == version {
                tbs.tlv_bytes()?;
            }
            let value = read(tbs)?;
            skip_rest(tbs)?;
            Ok(value)
        })?;
        skip_rest(certificate)?;
        Ok(value)
    })
}

/// The `notBefore` of a DER certificate, in seconds since the Unix epoch.
fn not_before(certificate: &[u8]) -> der::Result<u64> {
    use der::asn1::{GeneralizedTime, UtcTime};
    use der::{Decode, Reader, Tag};

    let not_before = read_tbs(certificate, |tbs| {
        // serialNumber, signature and issuer
        for _ in 0..3 {
            tbs.tlv_bytes()?;
        }
        tbs.sequence(|validity| -> der::Result<Duration> {
            let not_before = match Tag::peek(validity)? {
                Tag::UtcTime => UtcTime::decode(validity)?.to_unix_duration(),
                _ => GeneralizedTime::decode(validity)?.to_unix_duration(),
            };
            // notAfter
            validity.tlv_bytes()?;
            Ok(not_before)
        })
    })?;
    Ok(not_before.as_secs())
}

/// The `subjectPublicKeyInfo` of a DER certificate, with its tag and length.
fn subject_public_key_info(certificate: &[u8]) -> der::Result<&[u8]> {
    use der::Reader;

    read_tbs(certificate, |tbs| {
        // serialNumber, signature, issuer, validity and subject
        for _ in 0..5 {
            tbs.tlv_bytes()?;
        }
        tbs.tlv_bytes()
    })
}

/// The server's own certificate, which must be the first entry and X.509.
fn end_entity<'a>(certificate: &ServerCertificate<'a>) -> Result<CertificateDer<'a>, TlsError> {
    match certificate.entries.first() {
        Some(CertificateEntryRef::X509(der)) => Ok(CertificateDer::from(*der)),
        _ => Err(TlsError::DecodeError),
    }
}

/// Checks the `CertificateVerify` signature with the server certificate's `public_key`.
fn verify_signature(
    message: &[u8],
    public_key: &SubjectPublicKeyInfoDer<'_>,
    verify: &CertificateVerifyRef,
) -> Result<(), TlsError> {
    let key = webpki::RawPublicKeyEntity::try_from(public_key)
        .map_err(|e| refused(&e, TlsError::DecodeError))?;
    key.verify_signature(
        algorithm(verify.signature_scheme)?,
        message,
        verify.signature,
    )
    .map_err(|e| refused(&e, TlsError::InvalidSignature))
}

fn verify_certificate(
    host: &str,
    anchors: &[TrustAnchor<'_>],
    certificate: &ServerCertificate,
    now: u64,
) -> Result<(), TlsError> {
    let leaf = end_entity(certificate)?;
    let mut intermediates = heapless::Vec::<CertificateDer<'_>, MAX_CERTIFICATE_ENTRIES>::new();
    for entry in certificate.entries.iter().skip(1) {
        let CertificateEntryRef::X509(der) = entry else {
            return Err(TlsError::DecodeError);
        };
        intermediates
            .push(CertificateDer::from(*der))
            .map_err(|_| TlsError::InsufficientSpace)?;
    }

    let cert =
        webpki::EndEntityCert::try_from(&leaf).map_err(|e| refused(&e, TlsError::DecodeError))?;
    cert.verify_for_usage(
        algorithms::ALL,
        anchors,
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(now)),
        webpki::KeyUsage::server_auth(),
        None,
        None,
    )
    .map_err(|e| refused(&e, TlsError::InvalidCertificate))?;

    let name = ServerName::try_from(host).map_err(|_| TlsError::InvalidCertificate)?;
    cert.verify_is_valid_for_subject_name(&name)
        .map_err(|e| refused(&e, TlsError::InvalidCertificate))
}

#[cfg(all(test, feature = "std"))]
mod cert_verifier_tests {
    use super::*;
    use crate::config::{Aes128GcmSha256, InsecureIgnoreDates};
    #[cfg(any(feature = "p256", feature = "p384", feature = "rsa"))]
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::sign::Signer;
    use std::time::SystemTime;

    /// The DER bytes of `tests/data/<name>.pem`.
    macro_rules! der {
        ($name:literal) => {
            pem_parser::pem_to_der(include_str!(concat!("../tests/data/", $name, ".pem")))
        };
    }

    macro_rules! assert_matches {
        ($result:expr, $expected:pat) => {
            let result = $result;
            assert!(matches!(result, $expected), "{result:?}");
        };
    }

    type Verifier<'a> = CertVerifier<'a, Aes128GcmSha256, SystemTime, 4096>;

    /// The body of a TLS 1.3 Certificate message holding `chain`, as a server sends it.
    ///
    /// The verifier keeps its copy of the chain from these bytes, which
    /// `CertificateRef::add` leaves empty.
    fn message(chain: &[&[u8]]) -> std::vec::Vec<u8> {
        let u24 = |n: usize| u32::try_from(n).unwrap().to_be_bytes()[1..].to_vec();
        let mut entries = std::vec::Vec::new();
        for der in chain {
            entries.extend_from_slice(&u24(der.len()));
            entries.extend_from_slice(der);
            entries.extend_from_slice(&[0, 0]);
        }
        let mut message = std::vec![0];
        message.extend_from_slice(&u24(entries.len()));
        message.extend_from_slice(&entries);
        message
    }

    fn parse(message: &[u8]) -> ServerCertificate<'_> {
        ServerCertificate::parse(&mut crate::parse_buffer::ParseBuffer::from(message)).unwrap()
    }

    /// Runs `chain` through the verifier for `host`, with `ca` as the trust anchor.
    fn verify(ca: &[u8], chain: &[&[u8]], host: &str) -> Result<(), TlsError> {
        let message = message(chain);
        let mut verifier = Verifier::new(Certificate::X509(ca));
        verifier.set_hostname_verification(host)?;
        verifier.verify_certificate(&embassy_crypto::Sha256::new(), parse(&message))
    }

    /// The content a server signs in its `CertificateVerify`, for an empty transcript.
    fn signed_content() -> std::vec::Vec<u8> {
        let transcript = embassy_crypto::Sha256::new().finalize();
        certificate_verify_message(
            b"TLS 1.3, server CertificateVerify\x00",
            transcript.as_ref(),
        )
        .unwrap()
        .to_vec()
    }

    fn key(pem: &str) -> PKey<Private> {
        PKey::private_key_from_pem(pem.as_bytes()).unwrap()
    }

    /// Signs the `CertificateVerify` content with `digest`, and with RSA-PKCS#1 for an RSA key.
    #[cfg(any(feature = "p256", feature = "p384", feature = "rsa"))]
    fn sign(key: &PKey<Private>, digest: MessageDigest) -> std::vec::Vec<u8> {
        let mut signer = Signer::new(digest, key).unwrap();
        signer.sign_oneshot_to_vec(&signed_content()).unwrap()
    }

    /// Verifies `chain`, then a `CertificateVerify` with `scheme` and `signature`.
    fn verify_handshake(
        ca: &[u8],
        chain: &[&[u8]],
        scheme: SignatureScheme,
        signature: &[u8],
    ) -> Result<(), TlsError> {
        let message = message(chain);
        let mut verifier = Verifier::new(Certificate::X509(ca));
        verifier.set_hostname_verification("localhost")?;
        verifier.verify_certificate(&embassy_crypto::Sha256::new(), parse(&message))?;
        verifier.verify_signature(CertificateVerifyRef {
            signature_scheme: scheme,
            signature,
        })
    }

    /// Verifies `server_cert` against `ca` with the last byte of its signature changed.
    #[cfg(any(feature = "rsa", feature = "p384", feature = "ed25519"))]
    fn verify_with_a_changed_signature(
        ca: &[u8],
        mut server_cert: std::vec::Vec<u8>,
    ) -> Result<(), TlsError> {
        let last = server_cert.len() - 1;
        server_cert[last] = !server_cert[last];
        verify(ca, &[&server_cert], "localhost")
    }

    /// Runs `chain` through a verifier with `Clock`, for localhost, with `ca` as the anchor.
    fn verify_with_clock<Clock: TlsClock>(ca: &[u8], chain: &[&[u8]]) -> Result<(), TlsError> {
        let message = message(chain);
        let mut verifier = CertVerifier::<Aes128GcmSha256, Clock, 4096>::new(Certificate::X509(ca));
        verifier.set_hostname_verification("localhost")?;
        verifier.verify_certificate(&embassy_crypto::Sha256::new(), parse(&message))
    }

    #[test]
    fn a_certificate_is_refused_when_no_server_name_is_set() {
        let message = message(&[&der!("server-cert")]);
        let ca = der!("ca-cert");
        let mut verifier = Verifier::new(Certificate::X509(&ca));
        assert_matches!(
            verifier.verify_certificate(&embassy_crypto::Sha256::new(), parse(&message)),
            Err(TlsError::MissingServerName)
        );
    }

    // A bad chain without a server name reports the missing name, the setup fault, first.
    #[test]
    fn a_missing_server_name_is_reported_before_a_bad_chain() {
        let message = message(&[&der!("server-cert")]);
        let ca = der!("other-root-cert");
        let mut verifier = Verifier::new(Certificate::X509(&ca));
        assert_matches!(
            verifier.verify_certificate(&embassy_crypto::Sha256::new(), parse(&message)),
            Err(TlsError::MissingServerName)
        );
    }

    /// Runs a chain whose entry at `position` is a raw public key, with the server's certificate
    /// and intermediate around it.
    fn verify_with_raw_public_key(position: usize) -> Result<(), TlsError> {
        let (ca, server_cert, intermediate) =
            (der!("ca-cert"), der!("im-server-cert"), der!("im-cert"));
        let mut entries = std::vec![
            CertificateEntryRef::X509(&server_cert),
            CertificateEntryRef::X509(&intermediate),
        ];
        entries.insert(position, CertificateEntryRef::RawPublicKey(&[1, 2, 3]));
        // A Certificate message cannot hold a raw public key entry, so this one is built by hand.
        let mut chain = ServerCertificate::with_context(&[]);
        for entry in entries {
            chain.add(entry).unwrap();
        }
        let mut verifier = Verifier::new(Certificate::X509(&ca));
        verifier.set_hostname_verification("localhost")?;
        verifier.verify_certificate(&embassy_crypto::Sha256::new(), chain)
    }

    #[test]
    fn raw_public_key_as_the_server_certificate_is_rejected() {
        assert_matches!(verify_with_raw_public_key(0), Err(TlsError::DecodeError));
    }

    #[test]
    fn raw_public_key_among_the_intermediates_is_rejected() {
        assert_matches!(verify_with_raw_public_key(1), Err(TlsError::DecodeError));
    }

    // `open` sets the name before it sends the ClientHello, so a name the ClientHello's SNI check
    // could misjudge never reaches the wire.
    #[test]
    fn host_name_that_is_not_a_dns_name_or_ip_address_is_refused_before_the_handshake() {
        let ca = der!("ca-cert");
        for name in [
            "not a host",
            "",
            ".",
            "1.2.3",
            "999.1.1.1",
            "1.1.1.1.",
            "01.02.03.04",
            "example.com:443",
            "192.0.2.1:443",
            "[::1]",
            "fe80::1%eth0",
            "example..com",
            "-example.com",
            "*.example.com",
            "example.123",
        ] {
            let mut verifier = Verifier::new(Certificate::X509(&ca));
            assert_matches!(
                verifier.set_hostname_verification(name),
                Err(TlsError::InvalidCertificate)
            );
        }
    }

    #[test]
    fn server_cert_whose_dates_cannot_be_read_is_rejected_when_dates_are_ignored() {
        // The validity is two 13-byte UTCTimes. Changing the first one's tag makes it unreadable.
        let mut server_cert = der!("expired-server-cert");
        let validity = server_cert
            .windows(4)
            .position(|bytes| bytes == [0x30, 0x1e, 0x17, 0x0d])
            .unwrap();
        server_cert[validity + 2] = 0x04;
        assert_matches!(
            verify_with_clock::<InsecureIgnoreDates>(&der!("ca-cert"), &[&server_cert]),
            Err(TlsError::DecodeError)
        );
    }

    #[test]
    fn not_before_reads_utc_time_and_generalized_time() {
        // 2020-01-01 and 2090-01-01, at midnight UTC
        assert_eq!(
            not_before(&der!("expired-server-cert")).ok(),
            Some(1_577_836_800)
        );
        assert_eq!(
            not_before(&der!("future-server-cert")).ok(),
            Some(3_786_912_000)
        );
    }

    #[test]
    fn not_before_reads_a_certificate_with_and_without_the_version() {
        let tlv = |tag: u8, content: &[u8]| {
            let mut tlv = std::vec![tag, u8::try_from(content.len()).unwrap()];
            tlv.extend_from_slice(content);
            tlv
        };
        let validity = [tlv(0x17, b"200101000000Z"), tlv(0x17, b"210101000000Z")].concat();
        // serialNumber, signature, issuer, validity and subject
        let v1 = [
            tlv(0x02, &[1]),
            tlv(0x30, &[]),
            tlv(0x30, &[]),
            tlv(0x30, &validity),
            tlv(0x30, &[]),
        ]
        .concat();
        let v3 = [tlv(0xa0, &tlv(0x02, &[2])), v1.clone()].concat();
        for tbs in [v1, v3] {
            let certificate = tlv(0x30, &tlv(0x30, &tbs));
            assert_eq!(not_before(&certificate).ok(), Some(1_577_836_800));
        }
    }

    /// `ca-cert.pem` and the certificates it issued use P-256 keys. Without `p256` the verifier
    /// refuses every chain from them, so a test that expects a refusal would pass for the wrong
    /// reason.
    #[cfg(feature = "p256")]
    mod p256 {
        use super::*;

        #[test]
        fn server_cert_signed_by_the_ca_is_accepted() {
            assert_matches!(
                verify(&der!("ca-cert"), &[&der!("server-cert")], "localhost"),
                Ok(())
            );
        }

        // im-server-cert.pem names IP 127.0.0.1 in its subjectAltName.
        #[test]
        fn an_ip_address_server_name_is_checked_against_the_certificate() {
            let chain = [&der!("im-server-cert")[..], &der!("im-cert")];
            assert_matches!(verify(&der!("ca-cert"), &chain, "127.0.0.1"), Ok(()));
            assert_matches!(
                verify(&der!("ca-cert"), &chain, "127.0.0.2"),
                Err(TlsError::InvalidCertificate)
            );
        }

        #[test]
        fn server_cert_and_intermediate_are_accepted() {
            let chain = [&der!("im-server-cert")[..], &der!("im-cert")];
            assert_matches!(verify(&der!("ca-cert"), &chain, "localhost"), Ok(()));
        }

        /// A verifier whose `CERT_SIZE` holds the 91-byte P-256 key of `im-server-cert.pem`, but
        /// not that certificate, 442 bytes.
        type SmallVerifier<'a> = CertVerifier<'a, Aes128GcmSha256, SystemTime, 128>;

        #[test]
        fn cert_size_needs_to_hold_only_the_server_public_key() {
            let message = message(&[&der!("im-server-cert"), &der!("im-cert")]);
            let ca = der!("ca-cert");
            let mut verifier = SmallVerifier::new(Certificate::X509(&ca));
            verifier.set_hostname_verification("localhost").unwrap();
            let result =
                verifier.verify_certificate(&embassy_crypto::Sha256::new(), parse(&message));
            assert_matches!(result, Ok(()));
            let key = key(include_str!("../tests/data/im-server-key.pem"));
            let signature = sign(&key, MessageDigest::sha256());
            assert_matches!(
                verifier.verify_signature(CertificateVerifyRef {
                    signature_scheme: SignatureScheme::EcdsaSecp256r1Sha256,
                    signature: &signature,
                }),
                Ok(())
            );
        }

        #[test]
        fn chain_that_does_not_reach_the_ca_is_rejected() {
            let chain = [&der!("im-server-cert")[..], &der!("im-cert")];
            assert_matches!(
                verify(&der!("other-root-cert"), &chain, "localhost"),
                Err(TlsError::InvalidCertificate)
            );
        }

        // The server's own certificate comes first (RFC 9846, section 4.5.1). The intermediate is a
        // CA and is not valid for the name, so taking it as the server's certificate must fail.
        #[test]
        fn chain_with_the_intermediate_first_is_rejected() {
            let chain = [&der!("im-cert")[..], &der!("im-server-cert")];
            assert_matches!(
                verify(&der!("ca-cert"), &chain, "localhost"),
                Err(TlsError::InvalidCertificate)
            );
        }

        #[test]
        fn server_cert_for_another_name_is_rejected() {
            assert_matches!(
                verify(&der!("ca-cert"), &[&der!("server-cert")], "example.com"),
                Err(TlsError::InvalidCertificate)
            );
        }

        // TLS 1.3 names no scheme for P-256 with SHA-384, so the client does not advertise it.
        #[test]
        fn server_cert_signed_with_p256_and_sha384_is_rejected() {
            assert_matches!(
                verify(
                    &der!("ca-cert"),
                    &[&der!("sha384-server-cert")],
                    "localhost"
                ),
                Err(TlsError::InvalidCertificate)
            );
        }

        #[test]
        fn certificate_verify_with_p256_is_accepted() {
            let key = key(include_str!("../tests/data/server-key.pem"));
            let result = verify_handshake(
                &der!("ca-cert"),
                &[&der!("server-cert")],
                SignatureScheme::EcdsaSecp256r1Sha256,
                &sign(&key, MessageDigest::sha256()),
            );
            assert_matches!(result, Ok(()));
        }

        #[test]
        fn certificate_verify_with_a_wrong_signature_is_rejected() {
            let key = key(include_str!("../tests/data/server-key.pem"));
            let mut signature = sign(&key, MessageDigest::sha256());
            let last = signature.len() - 1;
            signature[last] ^= 1;
            let result = verify_handshake(
                &der!("ca-cert"),
                &[&der!("server-cert")],
                SignatureScheme::EcdsaSecp256r1Sha256,
                &signature,
            );
            assert_matches!(result, Err(TlsError::InvalidSignature));
        }

        #[test]
        fn certificate_verify_claiming_rsa_for_an_ecdsa_key_is_rejected() {
            let key = key(include_str!("../tests/data/server-key.pem"));
            let result = verify_handshake(
                &der!("ca-cert"),
                &[&der!("server-cert")],
                SignatureScheme::RsaPssRsaeSha256,
                &sign(&key, MessageDigest::sha256()),
            );
            assert!(result.is_err(), "{result:?}");
        }

        /// A clock of the application's own that does not have the time yet.
        struct UnsyncedClock;

        impl TlsClock for UnsyncedClock {
            fn now() -> Option<u64> {
                None
            }
        }

        #[test]
        fn expired_server_cert_is_rejected() {
            let chain = [&der!("expired-server-cert")[..]];
            assert_matches!(
                verify(&der!("ca-cert"), &chain, "localhost"),
                Err(TlsError::InvalidCertificate)
            );
        }

        #[test]
        fn expired_server_cert_is_accepted_by_any_clock_without_the_time() {
            let chain = [&der!("expired-server-cert")[..]];
            assert_matches!(
                verify_with_clock::<UnsyncedClock>(&der!("ca-cert"), &chain),
                Ok(())
            );
        }

        #[test]
        fn expired_server_cert_is_accepted_when_dates_are_ignored() {
            let chain = [&der!("expired-server-cert")[..]];
            assert_matches!(
                verify_with_clock::<InsecureIgnoreDates>(&der!("ca-cert"), &chain),
                Ok(())
            );
        }

        #[test]
        fn not_yet_valid_server_cert_is_accepted_when_dates_are_ignored() {
            let chain = [&der!("future-server-cert")[..]];
            assert_matches!(
                verify_with_clock::<InsecureIgnoreDates>(&der!("ca-cert"), &chain),
                Ok(())
            );
        }

        // im-cert.pem's notBefore is later than im-server-cert.pem's, so only the latest notBefore
        // of the chain falls within both certificates.
        #[test]
        fn intermediate_issued_after_the_server_cert_is_accepted_when_dates_are_ignored() {
            let chain = [&der!("im-server-cert")[..], &der!("im-cert")];
            assert_matches!(
                verify_with_clock::<InsecureIgnoreDates>(&der!("ca-cert"), &chain),
                Ok(())
            );
        }

        #[test]
        fn chain_whose_validity_periods_do_not_overlap_is_rejected_when_dates_are_ignored() {
            let chain = [&der!("late-im-server-cert")[..], &der!("expired-im-cert")];
            assert_matches!(
                verify_with_clock::<InsecureIgnoreDates>(&der!("ca-cert"), &chain),
                Err(TlsError::InvalidCertificate)
            );
        }

        #[test]
        fn ignoring_dates_keeps_the_name_check() {
            let ca = der!("ca-cert");
            let mut verifier = CertVerifier::<Aes128GcmSha256, InsecureIgnoreDates, 4096>::new(
                Certificate::X509(&ca),
            );
            verifier.set_hostname_verification("example.com").unwrap();
            let message = message(&[&der!("expired-server-cert")]);
            assert_matches!(
                verifier.verify_certificate(&embassy_crypto::Sha256::new(), parse(&message)),
                Err(TlsError::InvalidCertificate)
            );
        }

        /// A clock without the time, built on 2022-01-01.
        struct FloorIn2022;

        impl TlsClock for FloorIn2022 {
            fn now() -> Option<u64> {
                None
            }
            fn floor() -> u64 {
                1_640_995_200
            }
        }

        /// A clock without the time, built on 2019-01-01.
        struct FloorIn2019;

        impl TlsClock for FloorIn2019 {
            fn now() -> Option<u64> {
                None
            }
            fn floor() -> u64 {
                1_546_300_800
            }
        }

        // expired-server-cert.pem is valid in 2020 only.
        #[test]
        fn server_cert_that_expired_before_the_floor_is_rejected_without_the_time() {
            let chain = [&der!("expired-server-cert")[..]];
            assert_matches!(
                verify_with_clock::<FloorIn2022>(&der!("ca-cert"), &chain),
                Err(TlsError::InvalidCertificate)
            );
        }

        #[test]
        fn server_cert_issued_after_the_floor_is_accepted_without_the_time() {
            let chain = [&der!("expired-server-cert")[..]];
            assert_matches!(
                verify_with_clock::<FloorIn2019>(&der!("ca-cert"), &chain),
                Ok(())
            );
        }

        #[test]
        fn server_cert_valid_at_the_floor_is_accepted_without_the_time() {
            let chain = [&der!("server-cert")[..]];
            assert_matches!(
                verify_with_clock::<FloorIn2022>(&der!("ca-cert"), &chain),
                Ok(())
            );
        }

        /// Runs `chain` through a verifier for localhost that trusts any of `roots`.
        fn verify_with_anchors(roots: &[&[u8]], chain: &[&[u8]]) -> Result<(), TlsError> {
            let roots: std::vec::Vec<_> = roots.iter().map(|r| CertificateDer::from(*r)).collect();
            let anchors: std::vec::Vec<_> =
                roots.iter().map(|r| trust_anchor(r).unwrap()).collect();
            let message = message(chain);
            let mut verifier = Verifier::with_trust_anchors(&anchors);
            verifier.set_hostname_verification("localhost")?;
            verifier.verify_certificate(&embassy_crypto::Sha256::new(), parse(&message))
        }

        #[test]
        fn chain_to_any_of_several_anchors_is_accepted() {
            let chain = [&der!("im-server-cert")[..], &der!("im-cert")];
            let (other, p384, ca) = (
                der!("other-root-cert"),
                der!("p384-ca-cert"),
                der!("ca-cert"),
            );
            assert_matches!(verify_with_anchors(&[&other, &p384, &ca], &chain), Ok(()));
            assert_matches!(verify_with_anchors(&[&ca, &other], &chain), Ok(()));
        }

        #[test]
        fn chain_to_none_of_the_anchors_is_rejected() {
            let chain = [&der!("im-server-cert")[..], &der!("im-cert")];
            let (other, p384) = (der!("other-root-cert"), der!("p384-ca-cert"));
            assert_matches!(
                verify_with_anchors(&[&other, &p384], &chain),
                Err(TlsError::InvalidCertificate)
            );
        }

        #[test]
        fn no_anchors_trust_nothing() {
            assert_matches!(
                verify_with_anchors(&[], &[&der!("server-cert")]),
                Err(TlsError::InvalidCertificate)
            );
        }

        #[test]
        fn certificate_verify_is_checked_with_a_chain_to_one_of_several_anchors() {
            let (other, ca) = (der!("other-root-cert"), der!("ca-cert"));
            let roots = [
                CertificateDer::from(&other[..]),
                CertificateDer::from(&ca[..]),
            ];
            let anchors = [
                trust_anchor(&roots[0]).unwrap(),
                trust_anchor(&roots[1]).unwrap(),
            ];
            let message = message(&[&der!("server-cert")]);
            let mut verifier = Verifier::with_trust_anchors(&anchors);
            verifier.set_hostname_verification("localhost").unwrap();
            verifier
                .verify_certificate(&embassy_crypto::Sha256::new(), parse(&message))
                .unwrap();
            let key = key(include_str!("../tests/data/server-key.pem"));
            let signature = sign(&key, MessageDigest::sha256());
            assert_matches!(
                verifier.verify_signature(CertificateVerifyRef {
                    signature_scheme: SignatureScheme::EcdsaSecp256r1Sha256,
                    signature: &signature,
                }),
                Ok(())
            );
        }
    }

    #[test]
    fn a_trust_anchor_is_not_read_from_bytes_that_are_not_a_certificate() {
        let not_a_certificate = CertificateDer::from(&[0x30, 0x03, 0x02, 0x01, 0x01][..]);
        assert_matches!(trust_anchor(&not_a_certificate), Err(TlsError::DecodeError));
    }

    #[test]
    fn subject_public_key_info_reads_the_key_with_its_tag() {
        // A P-256 key: SEQUENCE { algorithm, BIT STRING of 66 bytes }, 91 bytes in all.
        let certificate = der!("server-cert");
        let key = subject_public_key_info(&certificate).unwrap();
        assert_eq!((key.len(), key[0]), (91, 0x30));
        let key = SubjectPublicKeyInfoDer::from(key);
        assert!(webpki::RawPublicKeyEntity::try_from(&key).is_ok());
    }

    #[cfg(feature = "p384")]
    mod p384 {
        use super::*;

        #[test]
        fn server_cert_signed_with_p384_and_sha384_is_accepted() {
            assert_matches!(
                verify(
                    &der!("p384-ca-cert"),
                    &[&der!("p384-server-cert")],
                    "localhost"
                ),
                Ok(())
            );
        }

        #[test]
        fn server_cert_signed_with_p384_and_sha256_is_rejected() {
            let chain = [&der!("p384-sha256-server-cert")[..]];
            assert_matches!(
                verify(&der!("p384-ca-cert"), &chain, "localhost"),
                Err(TlsError::InvalidCertificate)
            );
        }

        #[test]
        fn server_cert_with_a_changed_p384_signature_is_rejected() {
            assert_matches!(
                verify_with_a_changed_signature(&der!("p384-ca-cert"), der!("p384-server-cert")),
                Err(TlsError::InvalidCertificate)
            );
        }

        #[test]
        fn certificate_verify_with_p384_is_accepted() {
            let key = key(include_str!("../tests/data/p384-key-server-key.pem"));
            let result = verify_handshake(
                &der!("p384-ca-cert"),
                &[&der!("p384-key-server-cert")],
                SignatureScheme::EcdsaSecp384r1Sha384,
                &sign(&key, MessageDigest::sha384()),
            );
            assert_matches!(result, Ok(()));
        }
    }

    #[cfg(feature = "ed25519")]
    mod ed25519 {
        use super::*;

        fn sign_ed25519(key: &PKey<Private>) -> std::vec::Vec<u8> {
            let mut signer = Signer::new_without_digest(key).unwrap();
            signer.sign_oneshot_to_vec(&signed_content()).unwrap()
        }

        #[test]
        fn server_cert_signed_with_ed25519_is_accepted() {
            assert_matches!(
                verify(&der!("ed-ca-cert"), &[&der!("ed-server-cert")], "localhost"),
                Ok(())
            );
        }

        #[test]
        fn server_cert_with_a_changed_ed25519_signature_is_rejected() {
            assert_matches!(
                verify_with_a_changed_signature(&der!("ed-ca-cert"), der!("ed-server-cert")),
                Err(TlsError::InvalidCertificate)
            );
        }

        #[test]
        fn certificate_verify_with_ed25519_is_accepted() {
            let key = key(include_str!("../tests/data/ed-server-key.pem"));
            let result = verify_handshake(
                &der!("ed-ca-cert"),
                &[&der!("ed-server-cert")],
                SignatureScheme::Ed25519,
                &sign_ed25519(&key),
            );
            assert_matches!(result, Ok(()));
        }
    }

    #[cfg(feature = "rsa")]
    mod rsa {
        use super::*;
        use openssl::rsa::Padding;
        use openssl::sign::RsaPssSaltlen;

        fn sign_rsa_pss(key: &PKey<Private>, digest: MessageDigest) -> std::vec::Vec<u8> {
            let mut signer = Signer::new(digest, key).unwrap();
            signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
            signer
                .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .unwrap();
            signer.set_rsa_mgf1_md(digest).unwrap();
            signer.sign_oneshot_to_vec(&signed_content()).unwrap()
        }

        /// Verifies a `CertificateVerify` from `rsa-server-key.pem`, claiming `scheme`.
        fn verify_rsa(scheme: SignatureScheme, signature: &[u8]) -> Result<(), TlsError> {
            verify_handshake(
                &der!("rsa-ca-cert"),
                &[&der!("rsa-server-cert")],
                scheme,
                signature,
            )
        }

        fn rsa_key() -> PKey<Private> {
            key(include_str!("../tests/data/rsa-server-key.pem"))
        }

        /// A verifier whose `CERT_SIZE` is smaller than an RSA-2048 key, 294 bytes.
        type SmallVerifier<'a> = CertVerifier<'a, Aes128GcmSha256, SystemTime, 256>;

        #[test]
        fn a_server_key_larger_than_cert_size_is_refused() {
            let message = message(&[&der!("rsa-server-cert")]);
            let ca = der!("rsa-ca-cert");
            let mut verifier = SmallVerifier::new(Certificate::X509(&ca));
            verifier.set_hostname_verification("localhost").unwrap();
            assert_matches!(
                verifier.verify_certificate(&embassy_crypto::Sha256::new(), parse(&message)),
                Err(TlsError::OutOfMemory)
            );
        }

        // many-names-rsa-server-cert.pem is 5.5 KB, for rsa-server-key.pem.
        #[test]
        fn a_large_server_certificate_verifies_when_cert_size_holds_its_key() {
            let message = message(&[&der!("many-names-rsa-server-cert")]);
            let ca = der!("rsa-ca-cert");
            let mut verifier =
                CertVerifier::<Aes128GcmSha256, SystemTime, 512>::new(Certificate::X509(&ca));
            verifier.set_hostname_verification("localhost").unwrap();
            assert_matches!(
                verifier.verify_certificate(&embassy_crypto::Sha256::new(), parse(&message)),
                Ok(())
            );
            let signature = sign_rsa_pss(&rsa_key(), MessageDigest::sha256());
            assert_matches!(
                verifier.verify_signature(CertificateVerifyRef {
                    signature_scheme: SignatureScheme::RsaPssRsaeSha256,
                    signature: &signature,
                }),
                Ok(())
            );
        }

        #[test]
        fn server_cert_signed_with_rsa_is_accepted() {
            assert_matches!(
                verify(
                    &der!("rsa-ca-cert"),
                    &[&der!("rsa-server-cert")],
                    "localhost"
                ),
                Ok(())
            );
        }

        #[test]
        fn server_cert_with_a_changed_rsa_signature_is_rejected() {
            assert_matches!(
                verify_with_a_changed_signature(&der!("rsa-ca-cert"), der!("rsa-server-cert")),
                Err(TlsError::InvalidCertificate)
            );
        }

        #[test]
        fn certificate_verify_with_rsa_pss_and_sha256_is_accepted() {
            let signature = sign_rsa_pss(&rsa_key(), MessageDigest::sha256());
            assert_matches!(
                verify_rsa(SignatureScheme::RsaPssRsaeSha256, &signature),
                Ok(())
            );
        }

        #[test]
        fn certificate_verify_with_rsa_pss_and_sha384_is_accepted() {
            let signature = sign_rsa_pss(&rsa_key(), MessageDigest::sha384());
            assert_matches!(
                verify_rsa(SignatureScheme::RsaPssRsaeSha384, &signature),
                Ok(())
            );
        }

        #[test]
        fn certificate_verify_with_rsa_pss_and_sha512_is_accepted() {
            let signature = sign_rsa_pss(&rsa_key(), MessageDigest::sha512());
            assert_matches!(
                verify_rsa(SignatureScheme::RsaPssRsaeSha512, &signature),
                Ok(())
            );
        }

        #[test]
        fn certificate_verify_claiming_another_hash_than_it_used_is_rejected() {
            let signature = sign_rsa_pss(&rsa_key(), MessageDigest::sha256());
            assert_matches!(
                verify_rsa(SignatureScheme::RsaPssRsaeSha384, &signature),
                Err(TlsError::InvalidSignature)
            );
        }

        // RFC 9846, section 4.3.3: the rsa_pkcs1 schemes are for signatures in certificates only,
        // so a CertificateVerify that claims one is refused even when the client offers them.
        #[test]
        fn certificate_verify_with_rsa_pkcs1_is_rejected() {
            let signature = sign(&rsa_key(), MessageDigest::sha256());
            assert_matches!(
                verify_rsa(SignatureScheme::RsaPkcs1Sha256, &signature),
                Err(TlsError::InvalidSignatureScheme)
            );
        }

        #[test]
        fn certificate_verify_with_a_1024_bit_rsa_key_is_rejected() {
            let key = key(include_str!("../tests/data/rsa1024-server-key.pem"));
            let result = verify_handshake(
                &der!("rsa-ca-cert"),
                &[&der!("rsa1024-server-cert")],
                SignatureScheme::RsaPssRsaeSha256,
                &sign_rsa_pss(&key, MessageDigest::sha256()),
            );
            assert_matches!(result, Err(TlsError::InvalidSignature));
        }
    }
}

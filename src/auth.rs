//! Verification for OpenShell extension bearer credentials.

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::metadata::MetadataMap;
use tonic::Status;

pub const EXTENSION_JWT_TYP: &str = "openshell-ext+jwt";
pub const MAX_EXTENSION_TOKEN_TTL_SECS: i64 = 60 * 60;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CallerKind {
    Gateway,
    Supervisor,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ExtensionClaims {
    iss: String,
    aud: String,
    sub: String,
    iat: i64,
    exp: i64,
    jti: String,
    caller_kind: CallerKind,
    sandbox_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rcgen::{KeyPair, PKCS_ED25519};

    fn material() -> (KeyPair, ExtensionJwtVerifier) {
        let key = KeyPair::generate_for(&PKCS_ED25519).expect("Ed25519 key");
        let verifier = ExtensionJwtVerifier::from_pem(
            key.public_key_pem().as_bytes(),
            "gateway-a",
            "urn:openshell:extension:middleware:tenuo/authorization",
            Some("key-a".to_string()),
        )
        .expect("verifier");
        (key, verifier)
    }

    fn token(
        key: &KeyPair,
        kind: CallerKind,
        sandbox_id: Option<&str>,
        audience: &str,
        issued_at: i64,
        expires_at: i64,
    ) -> String {
        let issuer = "openshell-gateway:gateway-a";
        let sub = match sandbox_id {
            Some(value) => format!("spiffe://openshell/sandbox/{value}"),
            None => issuer.to_string(),
        };
        let claims = ExtensionClaims {
            iss: issuer.to_string(),
            aud: audience.to_string(),
            sub,
            iat: issued_at,
            exp: expires_at,
            jti: "token-a".to_string(),
            caller_kind: kind,
            sandbox_id: sandbox_id.map(str::to_string),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(EXTENSION_JWT_TYP.to_string());
        header.kid = Some("key-a".to_string());
        encode(
            &header,
            &claims,
            &EncodingKey::from_ed_pem(key.serialize_pem().as_bytes()).expect("encoding key"),
        )
        .expect("token")
    }

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64
    }

    #[test]
    fn accepts_gateway_and_supervisor_shapes() {
        let (key, verifier) = material();
        let now = now();
        let gateway = token(
            &key,
            CallerKind::Gateway,
            None,
            verifier.audience(),
            now,
            now + 300,
        );
        assert_eq!(
            verifier.verify(&gateway).expect("gateway").kind,
            CallerKind::Gateway
        );

        let supervisor = token(
            &key,
            CallerKind::Supervisor,
            Some("sandbox-a"),
            verifier.audience(),
            now,
            now + 300,
        );
        let caller = verifier.verify(&supervisor).expect("supervisor");
        assert_eq!(caller.kind, CallerKind::Supervisor);
        assert_eq!(caller.sandbox_id.as_deref(), Some("sandbox-a"));
    }

    #[test]
    fn rejects_wrong_audience_expiry_and_excessive_lifetime() {
        let (key, verifier) = material();
        let now = now();
        for candidate in [
            token(
                &key,
                CallerKind::Gateway,
                None,
                "wrong-audience",
                now,
                now + 300,
            ),
            token(
                &key,
                CallerKind::Gateway,
                None,
                verifier.audience(),
                now - 600,
                now - 300,
            ),
            token(
                &key,
                CallerKind::Gateway,
                None,
                verifier.audience(),
                now,
                now + MAX_EXTENSION_TOKEN_TTL_SECS + 1,
            ),
        ] {
            assert_eq!(
                verifier.verify(&candidate).expect_err("must deny").code(),
                tonic::Code::Unauthenticated
            );
        }
    }

    #[test]
    fn rejects_cross_kind_identity_confusion() {
        let (key, verifier) = material();
        let now = now();
        let gateway_with_sandbox = token(
            &key,
            CallerKind::Gateway,
            Some("sandbox-a"),
            verifier.audience(),
            now,
            now + 300,
        );
        assert!(verifier.verify(&gateway_with_sandbox).is_err());

        let supervisor_without_sandbox = token(
            &key,
            CallerKind::Supervisor,
            None,
            verifier.audience(),
            now,
            now + 300,
        );
        assert!(verifier.verify(&supervisor_without_sandbox).is_err());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedCaller {
    pub kind: CallerKind,
    pub sandbox_id: Option<String>,
    pub jti: String,
}

#[derive(Clone)]
pub struct ExtensionJwtVerifier {
    key: DecodingKey,
    issuer: String,
    audience: String,
    key_id: Option<String>,
}

impl ExtensionJwtVerifier {
    pub fn from_pem_file(
        path: &Path,
        gateway_id: &str,
        audience: &str,
        key_id: Option<String>,
    ) -> Result<Self, String> {
        let pem =
            fs::read(path).map_err(|error| format!("read OpenShell JWT public key: {error}"))?;
        Self::from_pem(&pem, gateway_id, audience, key_id)
    }

    pub fn from_pem(
        pem: &[u8],
        gateway_id: &str,
        audience: &str,
        key_id: Option<String>,
    ) -> Result<Self, String> {
        if gateway_id.is_empty() || audience.is_empty() {
            return Err("gateway id and audience must not be empty".to_string());
        }
        let key = DecodingKey::from_ed_pem(pem)
            .map_err(|_| "OpenShell JWT public key is not Ed25519 PEM".to_string())?;
        Ok(Self {
            key,
            issuer: format!("openshell-gateway:{gateway_id}"),
            audience: audience.to_string(),
            key_id,
        })
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    // `tonic::Status` is intentionally returned at this gRPC interceptor boundary.
    #[allow(clippy::result_large_err)]
    pub fn verify_metadata(&self, metadata: &MetadataMap) -> Result<AuthenticatedCaller, Status> {
        let value = metadata
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing extension bearer credential"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("invalid extension bearer credential"))?;
        let token = value
            .strip_prefix("Bearer ")
            .filter(|token| {
                !token.is_empty() && !token.bytes().any(|byte| byte.is_ascii_whitespace())
            })
            .ok_or_else(|| Status::unauthenticated("invalid extension bearer credential"))?;
        self.verify(token)
    }

    #[allow(clippy::result_large_err)]
    pub fn verify(&self, token: &str) -> Result<AuthenticatedCaller, Status> {
        let header = decode_header(token)
            .map_err(|_| Status::unauthenticated("invalid extension bearer credential"))?;
        if header.alg != Algorithm::EdDSA || header.typ.as_deref() != Some(EXTENSION_JWT_TYP) {
            return Err(Status::unauthenticated(
                "invalid extension bearer credential",
            ));
        }
        if let Some(expected) = &self.key_id {
            if header.kid.as_deref() != Some(expected.as_str()) {
                return Err(Status::unauthenticated(
                    "invalid extension bearer credential",
                ));
            }
        }

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["iss", "aud", "sub", "iat", "exp", "jti"]);
        validation.leeway = 30;
        validation.reject_tokens_expiring_in_less_than = 0;
        let claims = decode::<ExtensionClaims>(token, &self.key, &validation)
            .map_err(|_| Status::unauthenticated("invalid extension bearer credential"))?
            .claims;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
            });
        if claims.iss != self.issuer
            || claims.aud != self.audience
            || claims.jti.is_empty()
            || claims.exp <= claims.iat
            || claims.exp - claims.iat > MAX_EXTENSION_TOKEN_TTL_SECS
            || claims.iat > now.saturating_add(30)
        {
            return Err(Status::unauthenticated(
                "invalid extension bearer credential",
            ));
        }

        match claims.caller_kind {
            CallerKind::Gateway => {
                if claims.sandbox_id.is_some() || claims.sub != self.issuer {
                    return Err(Status::unauthenticated(
                        "invalid extension bearer credential",
                    ));
                }
            }
            CallerKind::Supervisor => {
                let sandbox_id = claims
                    .sandbox_id
                    .as_deref()
                    .filter(|sandbox_id| !sandbox_id.is_empty())
                    .ok_or_else(|| {
                        Status::unauthenticated("invalid extension bearer credential")
                    })?;
                if claims.sub != format!("spiffe://openshell/sandbox/{sandbox_id}") {
                    return Err(Status::unauthenticated(
                        "invalid extension bearer credential",
                    ));
                }
            }
        }

        Ok(AuthenticatedCaller {
            kind: claims.caller_kind,
            sandbox_id: claims.sandbox_id,
            jti: claims.jti,
        })
    }
}

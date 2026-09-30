//! Holder key and warrant for the task running in this sandbox.
//!
//! The key is generated here and never leaves the sandbox. The warrant is not
//! a secret: without the key it cannot produce a proof of possession. It is
//! read from `TENUO_WARRANT` or from a file that the operator may replace
//! while the proxy runs.

use base64::Engine;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tenuo::sdk::prelude::*;
use tenuo::{PublicKey, SigningKey, Warrant};

/// Local checks accept any warrant lifetime up to this bound. The middleware
/// enforces the operator's real maximum.
const LOCAL_MAX_LIFETIME: Duration = Duration::from_secs(30 * 24 * 3600);

#[derive(Debug)]
pub enum AuthorityError {
    Key(String),
    NoWarrant,
    Warrant(String),
    WrongHolder,
}

impl std::fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key(message) => write!(formatter, "holder key: {message}"),
            Self::NoWarrant => formatter.write_str("no warrant has been installed"),
            Self::Warrant(message) => write!(formatter, "warrant: {message}"),
            Self::WrongHolder => {
                formatter.write_str("the warrant is issued to a different holder key")
            }
        }
    }
}

impl std::error::Error for AuthorityError {}

/// Where the warrant comes from.
#[derive(Clone, Debug)]
pub enum WarrantSource {
    /// Encoded warrant or warrant stack, fixed for the process lifetime.
    Inline(String),
    /// Re-read on every call, so an installed or rotated warrant takes effect
    /// without a restart.
    File(PathBuf),
}

/// Create the holder key if it does not exist and return its public key.
pub fn ensure_key(path: &Path) -> Result<PublicKey, AuthorityError> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        let key = SigningKey::generate();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(path)
            .and_then(|mut file| file.write_all(&key.secret_key_bytes()))
            .map_err(|error| AuthorityError::Key(error.to_string()))?;
    }
    Ok(load_key(path)?.public_key())
}

pub fn load_key(path: &Path) -> Result<SigningKey, AuthorityError> {
    let secret = fs::read(path).map_err(|error| AuthorityError::Key(error.to_string()))?;
    let secret: [u8; 32] = secret
        .try_into()
        .map_err(|_| AuthorityError::Key("expected 32 bytes".to_string()))?;
    Ok(SigningKey::from_bytes(&secret))
}

fn create_private_dir(path: &Path) -> Result<(), AuthorityError> {
    fs::create_dir_all(path).map_err(|error| AuthorityError::Key(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| AuthorityError::Key(error.to_string()))?;
    }
    Ok(())
}

/// Decode a warrant or warrant stack.
///
/// Accepts the `_meta.tenuo.warrant` encoding (URL-safe base64 of a CBOR
/// stack), padded URL-safe or standard base64, and raw CBOR bytes.
pub fn decode_chain(bytes: &[u8]) -> Result<Vec<Warrant>, AuthorityError> {
    let text = std::str::from_utf8(bytes).ok().map(str::trim);
    let decoded = text.and_then(|text| {
        [
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &base64::engine::general_purpose::URL_SAFE,
            &base64::engine::general_purpose::STANDARD,
        ]
        .into_iter()
        .find_map(|engine| engine.decode(text).ok())
    });
    let raw = decoded.as_deref().unwrap_or(bytes);
    if let Ok(stack) = tenuo::wire::decode_stack(raw) {
        if !stack.0.is_empty() {
            return Ok(stack.0);
        }
    }
    tenuo::wire::decode(raw)
        .map(|warrant| vec![warrant])
        .map_err(|_| AuthorityError::Warrant("not a Tenuo warrant or warrant stack".to_string()))
}

/// Encode a chain the way `_meta.tenuo.warrant` carries it.
pub fn encode_chain(chain: &[Warrant]) -> Result<String, AuthorityError> {
    let stack = tenuo::wire::WarrantStack::new(chain.to_vec());
    let bytes = tenuo::wire::encode_stack(&stack)
        .map_err(|error| AuthorityError::Warrant(error.to_string()))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Validate `encoded` against the holder key and write it atomically.
pub fn install_warrant(
    key_path: &Path,
    warrant_path: &Path,
    encoded: &[u8],
) -> Result<Vec<Warrant>, AuthorityError> {
    let key = load_key(key_path)?;
    let chain = decode_chain(encoded)?;
    check_holder(&chain, &key.public_key())?;
    let text = encode_chain(&chain)?;
    if let Some(parent) = warrant_path.parent() {
        fs::create_dir_all(parent).map_err(|error| AuthorityError::Warrant(error.to_string()))?;
    }
    let staging = warrant_path.with_extension("tmp");
    fs::write(&staging, format!("{text}\n"))
        .and_then(|()| fs::rename(&staging, warrant_path))
        .map_err(|error| AuthorityError::Warrant(error.to_string()))?;
    Ok(chain)
}

fn check_holder(chain: &[Warrant], holder: &PublicKey) -> Result<(), AuthorityError> {
    let leaf = chain.last().ok_or(AuthorityError::NoWarrant)?;
    if leaf.authorized_holder() != holder {
        return Err(AuthorityError::WrongHolder);
    }
    Ok(())
}

/// The key plus the source of the current warrant.
pub struct Holder {
    key: SigningKey,
    source: WarrantSource,
}

/// A warrant chain ready to sign calls, with a local guard for early denial.
///
/// The guard trusts the chain's own root. It exists to give the agent a clear
/// error before a request leaves the sandbox; the OpenShell middleware is the
/// enforcement point and applies the operator's trust roots.
pub struct Presented {
    pub guard: Guard,
    pub authority: PresentedAuthority,
}

impl Holder {
    pub fn new(key: SigningKey, source: WarrantSource) -> Self {
        Self { key, source }
    }

    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    pub fn chain(&self) -> Result<Vec<Warrant>, AuthorityError> {
        let chain = match &self.source {
            WarrantSource::Inline(text) => decode_chain(text.as_bytes())?,
            WarrantSource::File(path) => match fs::read(path) {
                Ok(bytes) => decode_chain(&bytes)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(AuthorityError::NoWarrant)
                }
                Err(error) => return Err(AuthorityError::Warrant(error.to_string())),
            },
        };
        check_holder(&chain, &self.key.public_key())?;
        Ok(chain)
    }

    pub fn present(&self) -> Result<Presented, AuthorityError> {
        let chain = self.chain()?;
        let root = chain
            .first()
            .map(|warrant| warrant.issuer().clone())
            .ok_or(AuthorityError::NoWarrant)?;
        let mut authorizer = tenuo::Authorizer::new();
        authorizer.add_trusted_root(root);
        let guard = Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: LOCAL_MAX_LIFETIME,
            })
            .build()
            .map_err(|error| AuthorityError::Warrant(error.to_string()))?;
        let signer = Arc::new(tenuo::sdk::LocalSigner::new(self.key.clone()));
        let authority = PresentedAuthority::new(chain, signer)
            .map_err(|error| AuthorityError::Warrant(error.to_string()))?;
        Ok(Presented { guard, authority })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenuo::ConstraintSet;

    fn warrant_for(holder: &PublicKey) -> Warrant {
        Warrant::builder()
            .capability("read_logs", ConstraintSet::new())
            .holder(holder.clone())
            .ttl(Duration::from_secs(300))
            .build(&SigningKey::generate())
            .expect("warrant")
    }

    #[test]
    fn key_is_created_once_with_private_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tenuo/holder.key");
        let first = ensure_key(&path).unwrap();
        assert_eq!(ensure_key(&path).unwrap(), first);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn every_supported_encoding_decodes_to_the_same_chain() {
        let warrant = warrant_for(&SigningKey::generate().public_key());
        let stack =
            tenuo::wire::encode_stack(&tenuo::wire::WarrantStack::new(vec![warrant.clone()]))
                .unwrap();
        let single = tenuo::wire::encode(&warrant).unwrap();
        for encoded in [
            encode_chain(std::slice::from_ref(&warrant))
                .unwrap()
                .into_bytes(),
            base64::engine::general_purpose::STANDARD
                .encode(&stack)
                .into_bytes(),
            base64::engine::general_purpose::STANDARD
                .encode(&single)
                .into_bytes(),
            stack.clone(),
            single.clone(),
        ] {
            let chain = decode_chain(&encoded).unwrap();
            assert_eq!(chain.len(), 1);
            assert_eq!(chain[0].id(), warrant.id());
        }
        assert!(decode_chain(b"not a warrant").is_err());
    }

    #[test]
    fn install_rejects_a_warrant_for_another_key() {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("holder.key");
        let warrant_path = directory.path().join("warrant");
        let holder = ensure_key(&key_path).unwrap();

        let other = warrant_for(&SigningKey::generate().public_key());
        let encoded = encode_chain(&[other]).unwrap();
        assert!(matches!(
            install_warrant(&key_path, &warrant_path, encoded.as_bytes()),
            Err(AuthorityError::WrongHolder)
        ));
        assert!(!warrant_path.exists());

        let mine = warrant_for(&holder);
        let encoded = encode_chain(std::slice::from_ref(&mine)).unwrap();
        install_warrant(&key_path, &warrant_path, encoded.as_bytes()).unwrap();
        let reader = Holder::new(
            load_key(&key_path).unwrap(),
            WarrantSource::File(warrant_path),
        );
        assert_eq!(reader.chain().unwrap()[0].id(), mine.id());
    }

    #[test]
    fn a_missing_file_reports_no_warrant() {
        let directory = tempfile::tempdir().unwrap();
        let holder = Holder::new(
            SigningKey::generate(),
            WarrantSource::File(directory.path().join("absent")),
        );
        assert!(matches!(holder.chain(), Err(AuthorityError::NoWarrant)));
    }
}

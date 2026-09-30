//! The TLS listener's certificate: PEM files (certbot's fullchain.pem and privkey.pem), read again
//! whenever they change, so a renewal takes effect without a restart. Connections already open
//! keep the certificate they started with.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use rustls::ServerConfig;
use rustls::crypto::ring::default_provider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug)]
pub struct Certificate {
    cert: PathBuf,
    key: PathBuf,
    current: RwLock<(Arc<CertifiedKey>, Option<SystemTime>)>,
}

fn modified(p: &PathBuf) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

fn load(cert: &PathBuf, key: &PathBuf) -> Result<Arc<CertifiedKey>, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("{}: {e}", cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!("{}: no certificate in it", cert.display()));
    }
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    let signing = default_provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| format!("the private key: {e}"))?;
    let ck = CertifiedKey::new(chain, signing);
    ck.keys_match()
        .map_err(|e| format!("the key and certificate: {e}"))?;
    Ok(Arc::new(ck))
}

impl Certificate {
    /// Both files, now: a node told to serve TLS that can't doesn't start.
    pub fn open(cert: PathBuf, key: PathBuf) -> Result<Arc<Self>, String> {
        let ck = load(&cert, &key)?;
        let at = modified(&cert).max(modified(&key));
        Ok(Arc::new(Certificate {
            cert,
            key,
            current: RwLock::new((ck, at)),
        }))
    }

    /// Reads the files again if either changed. A bad renewal keeps the certificate in use.
    pub fn reload_if_changed(&self) {
        let at = modified(&self.cert).max(modified(&self.key));
        if at == self.current.read().map(|c| c.1).unwrap_or(None) {
            return;
        }
        match load(&self.cert, &self.key) {
            Ok(ck) => {
                if let Ok(mut c) = self.current.write() {
                    *c = (ck, at);
                }
                eprintln!("tls: certificate reloaded from {}", self.cert.display());
            }
            Err(e) => eprintln!("tls: certificate not reloaded, keeping the current one: {e}"),
        }
    }

    pub fn server_config(self: &Arc<Self>) -> Arc<ServerConfig> {
        let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default versions")
            .with_no_client_auth()
            .with_cert_resolver(self.clone());
        Arc::new(config)
    }
}

impl ResolvesServerCert for Certificate {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.read().ok().map(|c| c.0.clone())
    }
}

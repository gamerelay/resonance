//! What a node keeps between runs, in RESONANCE_STATE_DIR (default /var/lib/resonance; the
//! systemd unit's StateDirectory): its ed25519 key (`key`, 32 bytes, mode 0600, never leaves the
//! box) and, once joined, who it is to the control plane (`node.json`).

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Joined {
    pub node_id: String,
    pub region: String,
    /// The control plane, e.g. https://gamerelay.io.
    pub control: String,
    /// The API version it joined with (§5): its requests default to it.
    pub api_version: String,
}

pub struct State {
    dir: PathBuf,
}

impl State {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        State { dir: dir.into() }
    }

    pub fn from_env() -> Self {
        Self::new(
            std::env::var("RESONANCE_STATE_DIR")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "/var/lib/resonance".into()),
        )
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// This node's key, made on first use.
    pub fn key(&self) -> std::io::Result<SigningKey> {
        let path = self.dir.join("key");
        match fs::read(&path) {
            Ok(b) if b.len() == 32 => Ok(SigningKey::from_bytes(
                b.as_slice().try_into().expect("32 bytes"),
            )),
            Ok(_) => Err(std::io::Error::other(format!(
                "{} isn't a 32-byte key",
                path.display()
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.dir)?;
                fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
                let mut seed = [0u8; 32];
                getrandom::fill(&mut seed).map_err(|e| std::io::Error::other(e.to_string()))?;
                let mut f = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)?;
                f.write_all(&seed)?;
                f.sync_all()?;
                Ok(SigningKey::from_bytes(&seed))
            }
            Err(e) => Err(e),
        }
    }

    pub fn joined(&self) -> std::io::Result<Option<Joined>> {
        match fs::read(self.dir.join("node.json")) {
            Ok(b) => serde_json::from_slice(&b)
                .map(Some)
                .map_err(std::io::Error::other),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn save_joined(&self, j: &Joined) -> std::io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let tmp = self.dir.join("node.json.tmp");
        fs::write(
            &tmp,
            serde_json::to_vec_pretty(j).map_err(std::io::Error::other)?,
        )?;
        fs::rename(tmp, self.dir.join("node.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let mut p = std::env::temp_dir();
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        p.push(format!(
            "resonance-state-{}",
            r.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        p
    }

    #[test]
    fn the_key_is_made_once_private_and_kept() {
        let s = State::new(tmp());
        let k = s.key().unwrap();
        assert_eq!(s.key().unwrap().to_bytes(), k.to_bytes());
        let mode = fs::metadata(s.dir().join("key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        fs::write(s.dir().join("key"), b"short").unwrap();
        assert!(s.key().is_err(), "a damaged key isn't replaced silently");
        fs::remove_dir_all(s.dir()).unwrap();
    }

    #[test]
    fn joined_round_trips() {
        let s = State::new(tmp());
        assert_eq!(s.joined().unwrap(), None);
        let j = Joined {
            node_id: "rn_x".into(),
            region: "iad".into(),
            control: "https://gamerelay.io".into(),
            api_version: "2026-09-29".into(),
        };
        s.save_joined(&j).unwrap();
        assert_eq!(s.joined().unwrap(), Some(j));
        fs::remove_dir_all(s.dir()).unwrap();
    }
}

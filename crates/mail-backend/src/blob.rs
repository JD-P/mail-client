use crate::{BackendError, Result};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::fs;
use uuid::Uuid;

#[derive(Debug)]
pub(crate) struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub(crate) async fn open(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)
            .await
            .map_err(|source| BackendError::Io {
                path: root.clone(),
                source,
            })?;
        Ok(Self { root })
    }

    pub(crate) async fn put(&self, bytes: &[u8]) -> Result<String> {
        let hash = hex::encode(Sha256::digest(bytes));
        let destination = self.path(&hash);
        if fs::try_exists(&destination)
            .await
            .map_err(|source| BackendError::Io {
                path: destination.clone(),
                source,
            })?
        {
            return Ok(hash);
        }

        let parent = destination.parent().expect("blob path has parent");
        fs::create_dir_all(parent)
            .await
            .map_err(|source| BackendError::Io {
                path: parent.to_owned(),
                source,
            })?;
        let temporary = parent.join(format!(".{}.tmp", Uuid::new_v4()));
        fs::write(&temporary, bytes)
            .await
            .map_err(|source| BackendError::Io {
                path: temporary.clone(),
                source,
            })?;
        match fs::rename(&temporary, &destination).await {
            Ok(()) => Ok(hash),
            Err(source) if destination.exists() => {
                let _ = fs::remove_file(&temporary).await;
                let _ = source;
                Ok(hash)
            }
            Err(source) => Err(BackendError::Io {
                path: destination,
                source,
            }),
        }
    }

    pub(crate) async fn get(&self, hash: &str) -> Result<Vec<u8>> {
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(BackendError::InvalidInput("invalid blob hash".into()));
        }
        let path = self.path(hash);
        let bytes = fs::read(&path).await.map_err(|source| BackendError::Io {
            path: path.clone(),
            source,
        })?;
        if hex::encode(Sha256::digest(&bytes)) != hash {
            return Err(BackendError::CorruptBlob {
                hash: hash.to_owned(),
            });
        }
        Ok(bytes)
    }

    fn path(&self, hash: &str) -> PathBuf {
        self.root.join(&hash[..2]).join(&hash[2..])
    }
}

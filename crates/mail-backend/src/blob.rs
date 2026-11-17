use crate::{BackendError, Result};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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

    pub(crate) async fn put_reader<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        maximum_bytes: u64,
    ) -> Result<(String, u64)> {
        let incoming = self.root.join("incoming");
        fs::create_dir_all(&incoming)
            .await
            .map_err(|source| BackendError::Io {
                path: incoming.clone(),
                source,
            })?;
        let temporary = incoming.join(format!("{}.tmp", Uuid::new_v4()));
        let mut file = fs::File::create(&temporary)
            .await
            .map_err(|source| BackendError::Io {
                path: temporary.clone(),
                source,
            })?;
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = reader
                .read(&mut buffer)
                .await
                .map_err(|source| BackendError::Io {
                    path: temporary.clone(),
                    source,
                })?;
            if read == 0 {
                break;
            }
            size = size.saturating_add(read as u64);
            if size > maximum_bytes {
                drop(file);
                let _ = fs::remove_file(&temporary).await;
                return Err(BackendError::MessageTooLarge {
                    actual: usize::try_from(size).unwrap_or(usize::MAX),
                    limit: usize::try_from(maximum_bytes).unwrap_or(usize::MAX),
                });
            }
            hasher.update(&buffer[..read]);
            file.write_all(&buffer[..read])
                .await
                .map_err(|source| BackendError::Io {
                    path: temporary.clone(),
                    source,
                })?;
        }
        file.flush().await.map_err(|source| BackendError::Io {
            path: temporary.clone(),
            source,
        })?;
        drop(file);
        let hash = hex::encode(hasher.finalize());
        let destination = self.path(&hash);
        let parent = destination.parent().expect("blob path has parent");
        fs::create_dir_all(parent)
            .await
            .map_err(|source| BackendError::Io {
                path: parent.to_owned(),
                source,
            })?;
        match fs::rename(&temporary, &destination).await {
            Ok(()) => Ok((hash, size)),
            Err(source) if destination.exists() => {
                let _ = fs::remove_file(&temporary).await;
                let _ = source;
                Ok((hash, size))
            }
            Err(source) => Err(BackendError::Io {
                path: destination,
                source,
            }),
        }
    }

    pub(crate) async fn stream_to<W: AsyncWrite + Unpin>(
        &self,
        hash: &str,
        writer: &mut W,
        maximum_bytes: u64,
    ) -> Result<u64> {
        validate_hash(hash)?;
        let path = self.path(hash);
        let mut file = fs::File::open(&path)
            .await
            .map_err(|source| BackendError::Io {
                path: path.clone(),
                source,
            })?;
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .await
                .map_err(|source| BackendError::Io {
                    path: path.clone(),
                    source,
                })?;
            if read == 0 {
                break;
            }
            size = size.saturating_add(read as u64);
            if size > maximum_bytes {
                return Err(BackendError::MessageTooLarge {
                    actual: usize::try_from(size).unwrap_or(usize::MAX),
                    limit: usize::try_from(maximum_bytes).unwrap_or(usize::MAX),
                });
            }
            hasher.update(&buffer[..read]);
            writer
                .write_all(&buffer[..read])
                .await
                .map_err(|source| BackendError::Io {
                    path: path.clone(),
                    source,
                })?;
        }
        if hex::encode(hasher.finalize()) != hash {
            return Err(BackendError::CorruptBlob {
                hash: hash.to_owned(),
            });
        }
        Ok(size)
    }

    fn path(&self, hash: &str) -> PathBuf {
        self.root.join(&hash[..2]).join(&hash[2..])
    }
}

fn validate_hash(hash: &str) -> Result<()> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BackendError::InvalidInput("invalid blob hash".into()));
    }
    Ok(())
}

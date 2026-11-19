use crate::{BackendError, Result};
use lizard_verified_kernel::charge_u64;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use uuid::Uuid;

pub(crate) struct BlobStore {
    root: PathBuf,
    budget: Arc<crate::storage::StorageBudget>,
    write_locks: Mutex<HashMap<String, Weak<Mutex<()>>>>,
}

impl BlobStore {
    pub(crate) async fn open(
        root: PathBuf,
        budget: Arc<crate::storage::StorageBudget>,
    ) -> Result<Self> {
        fs::create_dir_all(&root)
            .await
            .map_err(|source| crate::error::io_error(root.clone(), source))?;
        Ok(Self {
            root,
            budget,
            write_locks: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) async fn put(&self, bytes: &[u8]) -> Result<String> {
        let hash = hex::encode(Sha256::digest(bytes));
        let write_lock = self.write_lock(&hash).await;
        let _write_guard = write_lock.lock().await;
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
        if let Err(source) = fs::create_dir_all(parent).await {
            return Err(crate::error::io_error(parent.to_owned(), source));
        }
        let temporary = parent.join(format!(".{}.tmp", Uuid::new_v4()));
        let mut reservation = self.budget.start_reservation().await?;
        reservation.grow(bytes.len() as u64)?;
        if let Err(source) = fs::write(&temporary, bytes).await {
            let _ = fs::remove_file(&temporary).await;
            return Err(crate::error::io_error(temporary, source));
        }
        reservation.materialized(bytes.len() as u64)?;
        match fs::rename(&temporary, &destination).await {
            Ok(()) => {
                reservation.commit(bytes.len() as u64)?;
                Ok(hash)
            }
            Err(_source) if destination.exists() => {
                let _ = fs::remove_file(&temporary).await;
                reservation.commit(0)?;
                Ok(hash)
            }
            Err(source) => {
                let _ = fs::remove_file(&temporary).await;
                Err(crate::error::io_error(destination, source))
            }
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

    /// Remove a blob only after its caller has established that no durable
    /// database row references it. The per-hash writer lock prevents racing a
    /// concurrent content-addressed insertion of the same bytes.
    pub(crate) async fn remove_unreferenced(&self, hash: &str) -> Result<bool> {
        validate_hash(hash)?;
        let write_lock = self.write_lock(hash).await;
        let _write_guard = write_lock.lock().await;
        let path = self.path(hash);
        match fs::remove_file(&path).await {
            Ok(()) => Ok(true),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(BackendError::Io { path, source }),
        }
    }

    pub(crate) async fn put_reader<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        maximum_bytes: u64,
    ) -> Result<(String, u64)> {
        let incoming = self.root.join("incoming");
        fs::create_dir_all(&incoming)
            .await
            .map_err(|source| crate::error::io_error(incoming.clone(), source))?;
        let temporary = incoming.join(format!("{}.tmp", Uuid::new_v4()));
        let mut reservation = self.budget.start_reservation().await?;
        let mut file = fs::File::create(&temporary)
            .await
            .map_err(|source| crate::error::io_error(temporary.clone(), source))?;
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = match reader.read(&mut buffer).await {
                Ok(read) => read,
                Err(source) => {
                    drop(file);
                    let _ = fs::remove_file(&temporary).await;
                    return Err(crate::error::io_error(temporary, source));
                }
            };
            if read == 0 {
                break;
            }
            let Some(next_size) = charge_u64(size, read as u64, maximum_bytes) else {
                drop(file);
                let _ = fs::remove_file(&temporary).await;
                return Err(BackendError::MessageTooLarge {
                    actual: usize::try_from(size.saturating_add(read as u64)).unwrap_or(usize::MAX),
                    limit: usize::try_from(maximum_bytes).unwrap_or(usize::MAX),
                });
            };
            size = next_size;
            hasher.update(&buffer[..read]);
            if let Err(error) = reservation.grow(read as u64) {
                drop(file);
                let _ = fs::remove_file(&temporary).await;
                return Err(error);
            }
            if let Err(source) = file.write_all(&buffer[..read]).await {
                drop(file);
                let _ = fs::remove_file(&temporary).await;
                return Err(crate::error::io_error(temporary, source));
            }
            reservation.materialized(read as u64)?;
        }
        if let Err(source) = file.sync_all().await {
            drop(file);
            let _ = fs::remove_file(&temporary).await;
            return Err(crate::error::io_error(temporary, source));
        }
        drop(file);
        let hash = hex::encode(hasher.finalize());
        let write_lock = self.write_lock(&hash).await;
        let _write_guard = write_lock.lock().await;
        let destination = self.path(&hash);
        if fs::try_exists(&destination)
            .await
            .map_err(|source| crate::error::io_error(destination.clone(), source))?
        {
            let _ = fs::remove_file(&temporary).await;
            reservation.commit(0)?;
            return Ok((hash, size));
        }
        let parent = destination.parent().expect("blob path has parent");
        if let Err(source) = fs::create_dir_all(parent).await {
            let _ = fs::remove_file(&temporary).await;
            return Err(crate::error::io_error(parent.to_owned(), source));
        }
        match fs::rename(&temporary, &destination).await {
            Ok(()) => {
                reservation.commit(size)?;
                Ok((hash, size))
            }
            Err(_source) if destination.exists() => {
                let _ = fs::remove_file(&temporary).await;
                reservation.commit(0)?;
                Ok((hash, size))
            }
            Err(source) => {
                let _ = fs::remove_file(&temporary).await;
                Err(crate::error::io_error(destination, source))
            }
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
            let Some(next_size) = charge_u64(size, read as u64, maximum_bytes) else {
                return Err(BackendError::MessageTooLarge {
                    actual: usize::try_from(size.saturating_add(read as u64)).unwrap_or(usize::MAX),
                    limit: usize::try_from(maximum_bytes).unwrap_or(usize::MAX),
                });
            };
            size = next_size;
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

    async fn write_lock(&self, hash: &str) -> Arc<Mutex<()>> {
        let mut locks = self.write_locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(hash).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(hash.to_owned(), Arc::downgrade(&lock));
        lock
    }

    pub(crate) fn root(&self) -> &std::path::Path {
        &self.root
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

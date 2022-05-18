use anyhow::{anyhow, Context, Error};
pub use libsse::storage::object::ObjectId;
use libsse::storage::object::PersistentObject;
pub use libsse::storage::object::PersistentObjectType;
use libsse::storage::StorageError;
pub use libsse::storage::*;
pub use libsse_auth::session::AuthSession;
pub use parking_lot::Mutex;
use random_access_storage::RandomAccess;
use std::io::{Read, SeekFrom};
use std::io::{Seek, Write};
use std::ops::Drop;
use std::sync::Arc;

/// Random access secure storage
#[derive(Debug)]
pub struct RandomAccessSse {
    storage: Arc<Mutex<Storage>>,
    object: PersistentObject,
    length: u64,
    auto_sync: bool,
}

impl RandomAccessSse {
    /// Create a new instance.
    #[allow(clippy::new_ret_no_self)]
    pub async fn open<'a>(
        storage: Arc<Mutex<Storage>>,
        session: AuthSession,
        obj_id: ObjectId,
        obj_type: PersistentObjectType,
        storage_id: u32,
        flags: u32,
        attributes: Option<&'a PersistentObject>,
    ) -> Result<RandomAccessSse, Error> {
        Self::builder(storage, session, obj_id)
            .obj_type(obj_type)
            .storage_id(storage_id)
            .flags(flags)
            .attributes(attributes)
            .auto_sync(true)
            .build()
            .await
    }

    pub fn builder<'a>(
        storage: Arc<Mutex<Storage>>,
        session: AuthSession,
        obj_id: ObjectId,
    ) -> SseBuilder<'a> {
        SseBuilder::new(storage, session, obj_id)
    }
}

#[async_trait::async_trait]
impl RandomAccess for RandomAccessSse {
    type Error = Box<dyn std::error::Error + Sync + Send>;

    async fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), Self::Error> {
        let mut file = self
            .object
            .inner()
            .file()
            .expect("self.object.inner.file was None.");
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&data)?;
        if self.auto_sync {
            file.sync_all()?;
        }

        // We've changed the length of our file.
        let new_len = offset + (data.len() as u64);
        if new_len > self.length {
            self.length = new_len;
        }

        Ok(())
    }

    async fn read(&mut self, offset: u64, length: u64) -> Result<Vec<u8>, Self::Error> {
        if (offset + length) as u64 > self.length {
            return Err(anyhow!(
                "Read bounds exceeded. {} < {}..{}",
                self.length,
                offset,
                offset + length
            )
            .into());
        }

        let mut file = self
            .object
            .inner()
            .file()
            .expect("self.object.inner.file was None.");
        let mut buffer = vec![0; length as usize];
        file.seek(SeekFrom::Start(offset))?;
        let _bytes_read = file.read(&mut buffer[..])?;
        Ok(buffer)
    }

    async fn read_to_writer(
        &mut self,
        _offset: u64,
        _length: u64,
        _buf: &mut (impl async_std::io::Write + Send),
    ) -> Result<(), Self::Error> {
        unimplemented!()
    }

    async fn del(&mut self, _offset: u64, _length: u64) -> Result<(), Self::Error> {
        unimplemented!()
    }

    async fn truncate(&mut self, length: u64) -> Result<(), Self::Error> {
        let file = self
            .object
            .inner()
            .file()
            .expect("self.object.inner.file was None.");
        self.length = length as u64;
        file.set_len(self.length)?;
        if self.auto_sync {
            file.sync_all()?;
        }
        Ok(())
    }

    async fn len(&self) -> Result<u64, Self::Error> {
        Ok(self.length)
    }

    async fn is_empty(&mut self) -> Result<bool, Self::Error> {
        Ok(self.length == 0)
    }

    async fn sync_all(&mut self) -> Result<(), Self::Error> {
        if !self.auto_sync {
            let file = self
                .object
                .inner()
                .file()
                .expect("self.object.inner.file was None.");
            file.sync_all()?;
        }
        Ok(())
    }
}

impl Drop for RandomAccessSse {
    /// Flush the object on drop
    fn drop(&mut self) {
        if let Some(file) = &self.object.inner().file() {
            let _ = file.sync_all();
        }
    }
}

pub struct SseBuilder<'a> {
    storage: Arc<Mutex<Storage>>,
    session: AuthSession,
    obj_id: ObjectId,
    /// TODO: Store keypairs in CryptoKeypair objects
    obj_type: PersistentObjectType,
    storage_id: u32,
    flags: u32,
    attributes: Option<&'a PersistentObject>,
    auto_sync: bool,
}

impl<'a> SseBuilder<'a> {
    pub fn new(storage: Arc<Mutex<Storage>>, session: AuthSession, obj_id: ObjectId) -> Self {
        Self {
            storage,
            session,
            obj_id,
            obj_type: PersistentObjectType::Data,
            storage_id: 0,
            flags: 0,
            attributes: None,
            auto_sync: true,
        }
    }

    pub fn obj_type(mut self, obj_type: PersistentObjectType) -> Self {
        self.obj_type = obj_type;
        self
    }

    pub fn storage_id(mut self, storage_id: u32) -> Self {
        self.storage_id = storage_id;
        self
    }

    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    pub fn attributes(mut self, attributes: Option<&'a PersistentObject>) -> Self {
        self.attributes = attributes;
        self
    }

    pub fn auto_sync(mut self, auto_sync: bool) -> Self {
        self.auto_sync = auto_sync;
        self
    }

    pub async fn build(self) -> Result<RandomAccessSse, Error> {
        let session = self.session.clone();

        let object_ = self.storage.lock().create_object(
            session,
            self.obj_id.clone(),
            self.obj_type,
            self.storage_id,
            self.flags,
            self.attributes,
        );

        let object: PersistentObject;

        if object_.is_err() {
            let err = object_.unwrap_err();

            if err == StorageError::AccessConflict {
                object = self.storage.lock().open_object(
                    self.session,
                    self.obj_id,
                    self.storage_id,
                    self.flags,
                )?;
            } else {
                return Err(err)
                    .with_context(|| "Error creating or opening data from the secure storage");
            }
        } else {
            object = object_.unwrap();
        }

        object.inner().file().unwrap().sync_all()?;

        let metadata = object.inner().file().unwrap().metadata()?;

        Ok(RandomAccessSse {
            storage: self.storage,
            object: object,
            length: metadata.len(),
            auto_sync: self.auto_sync,
        })
    }
}

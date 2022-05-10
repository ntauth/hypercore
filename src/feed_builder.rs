use ed25519_dalek::{PublicKey, SecretKey};

use crate::bitfield::Bitfield;
use crate::crypto::Merkle;
use crate::storage::Storage;
use random_access_storage::RandomAccess;
use std::fmt::Debug;
use tree_index::TreeIndex;

use crate::Feed;
use anyhow::Result;

/// Construct a new `Feed` instance.
// TODO: make this an actual builder pattern.
// https://deterministic.space/elegant-apis-in-rust.html#builder-pattern
#[derive(Debug)]
pub struct FeedBuilder<T>
where
    T: RandomAccess + Debug,
{
    storage: Storage<T>,
    public_key: PublicKey,
    secret_key: Option<SecretKey>,
}

impl<T> FeedBuilder<T>
where
    T: RandomAccess<Error = Box<dyn std::error::Error + Send + Sync>> + Debug + Send,
{
    /// Create a new instance.
    #[inline]
    pub fn new(public_key: PublicKey, storage: Storage<T>) -> Self {
        Self {
            storage,
            public_key,
            secret_key: None,
        }
    }

    /// Set the secret key.
    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    /// Finalize the builder.
    #[inline]
    pub async fn build(mut self) -> Result<Feed<T>> {
        // Write the partial keypair
        self.storage.write_public_key(&self.public_key).await?;

        let mut secret_key: Option<SecretKey> = None;

        if self.secret_key.is_some() {
            let unwrapped_secret_key = self.secret_key.unwrap();
            secret_key = Some(SecretKey::from_bytes(unwrapped_secret_key.as_bytes())?);

            self.storage
                .write_secret_key(&unwrapped_secret_key)
                .await?;
        }

        let (bitfield, tree) = if let Ok(bitfield) = self.storage.read_bitfield().await {
            Bitfield::from_slice(&bitfield)
        } else {
            Bitfield::new()
        };
        use crate::storage::Node;

        let mut tree = TreeIndex::new(tree);
        let mut roots = vec![];
        flat_tree::full_roots(tree.blocks() * 2, &mut roots);
        let mut result: Vec<Option<Node>> = vec![None; roots.len()];

        for i in 0..roots.len() {
            let node = self.storage.get_node(roots[i] as u64).await?;
            let idx = roots
                .iter()
                .position(|&x| x == node.index)
                .ok_or_else(|| anyhow::anyhow!("Couldnt find idx of node"))?;
            result[idx] = Some(node);
        }

        let roots = result
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| anyhow::anyhow!("Roots contains undefined nodes"))?;

        let byte_length = roots.iter().fold(0, |acc, node| acc + node.length);

        Ok(Feed {
            merkle: Merkle::from_nodes(roots),
            byte_length,
            length: tree.blocks(),
            bitfield,
            tree,
            public_key: self.public_key,
            secret_key: secret_key,
            storage: self.storage,
            peers: vec![],
        })
    }
}

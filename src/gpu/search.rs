/// GPU-accelerated vanity address search using Metal
///
/// This module implements a hybrid CPU/GPU pipeline:
/// 1. CPU threads generate keypairs (secp256k1 - can't be GPU accelerated)
/// 2. GPU computes Keccak-256 hashes in batches
/// 3. CPU checks pattern matches on resulting addresses

use super::{GpuError, pipeline::GpuHasher};
use crate::address::{generate_keypair_direct, private_key_to_hex, raw_address_to_base58};
use crate::search::{VanityConfig, VanitySearcher, FoundAddress};
use crossbeam_channel::{bounded, Sender, Receiver};
use secp256k1::SecretKey;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;

/// Batch size for GPU hashing (tune for optimal performance)
/// Increased from 4096 to better amortize GPU overhead
const GPU_BATCH_SIZE: usize = 16384;

/// Channel capacity for producer-consumer queues
/// Reduced since larger batches mean fewer total messages
const CHANNEL_CAPACITY: usize = 4096;

/// Keypair with serialized public key ready for GPU
struct KeypairBatch {
    secret_key: SecretKey,
    public_key_bytes: [u8; 64],
}

/// GPU-accelerated continuous search
///
/// This function spawns an optimized hybrid CPU/GPU pipeline:
/// - CPU worker threads generate keypairs
/// - GPU hasher thread: batches, hashes on GPU, and checks patterns inline
///
/// Optimizations:
/// - Pattern matching is done inline (no separate matcher thread)
/// - Larger batch size (16384) to amortize GPU overhead
/// - Reduced channel hops for lower latency
///
/// # Arguments
/// * `config` - Pattern matching configuration
/// * `num_threads` - Number of CPU worker threads for keypair generation
/// * `sender` - Channel to send found addresses
/// * `running` - Atomic flag to control shutdown
/// * `attempts` - Atomic counter for total attempts
///
/// # Returns
/// `Ok(())` on successful initialization, `Err(GpuError)` if GPU setup fails
pub fn search_continuous_gpu(
    config: VanityConfig,
    num_threads: usize,
    sender: mpsc::Sender<FoundAddress>,
    running: Arc<AtomicBool>,
    attempts: Arc<AtomicU64>,
) -> Result<(), GpuError> {
    // Initialize GPU context
    let context = super::initialize()?;
    let hasher = Arc::new(GpuHasher::new(context)?);

    // Create channel for keypair pipeline (only one channel needed now)
    let (keypair_tx, keypair_rx): (Sender<KeypairBatch>, Receiver<KeypairBatch>) =
        bounded(CHANNEL_CAPACITY);

    // Spawn CPU worker threads (keypair generation)
    for _ in 0..num_threads {
        let keypair_tx = keypair_tx.clone();
        let running = running.clone();

        thread::spawn(move || {
            cpu_worker(keypair_tx, running);
        });
    }
    drop(keypair_tx); // Drop original sender so channel closes when workers finish

    // Spawn GPU hasher thread (now does hashing AND matching inline)
    let hasher_clone = hasher.clone();
    let running_clone = running.clone();
    let attempts_clone = attempts.clone();
    let searcher = Arc::new(VanitySearcher::new(config));
    thread::spawn(move || {
        gpu_hasher_worker(hasher_clone, keypair_rx, searcher, sender, running_clone, attempts_clone);
    });

    Ok(())
}

/// CPU worker: Generate keypairs and serialize public keys
fn cpu_worker(
    keypair_tx: Sender<KeypairBatch>,
    running: Arc<AtomicBool>,
) {
    while running.load(Ordering::Relaxed) {
        // Generate keypair
        let (secret_key, public_key) = generate_keypair_direct();

        // Serialize public key (uncompressed format, skip 0x04 prefix)
        let public_key_bytes = public_key.serialize_uncompressed();
        let mut pub_key_64 = [0u8; 64];
        pub_key_64.copy_from_slice(&public_key_bytes[1..]); // Skip first byte (0x04)

        let batch_item = KeypairBatch {
            secret_key,
            public_key_bytes: pub_key_64,
        };

        // Send to GPU queue (if send fails, channel is closed, so exit)
        if keypair_tx.send(batch_item).is_err() {
            break;
        }
    }
}

/// GPU hasher worker: Collect batches, compute Keccak-256 on GPU, and check patterns inline
///
/// Optimized to eliminate the separate matcher thread by doing pattern matching
/// immediately after GPU hashing, reducing latency and channel overhead.
fn gpu_hasher_worker(
    hasher: Arc<GpuHasher>,
    keypair_rx: Receiver<KeypairBatch>,
    searcher: Arc<VanitySearcher>,
    sender: mpsc::Sender<FoundAddress>,
    running: Arc<AtomicBool>,
    attempts: Arc<AtomicU64>,
) {
    let mut batch = Vec::with_capacity(GPU_BATCH_SIZE);
    let mut secret_keys = Vec::with_capacity(GPU_BATCH_SIZE);

    while running.load(Ordering::Relaxed) {
        // Collect a batch of public keys
        batch.clear();
        secret_keys.clear();

        // Optimized batch collection: use try_recv for fast filling
        // First, do a blocking recv to wait for at least one item
        match keypair_rx.recv() {
            Ok(item) => {
                batch.push(item.public_key_bytes);
                secret_keys.push(item.secret_key);
            }
            Err(_) => {
                // Channel closed, exit
                break;
            }
        }

        // Then quickly collect more items without blocking
        while batch.len() < GPU_BATCH_SIZE {
            match keypair_rx.try_recv() {
                Ok(item) => {
                    batch.push(item.public_key_bytes);
                    secret_keys.push(item.secret_key);
                }
                Err(_) => {
                    // No more items available right now, process what we have
                    break;
                }
            }
        }

        // Hash batch on GPU
        match hasher.hash_batch(&batch) {
            Ok(hashes) => {
                // Update attempts counter
                attempts.fetch_add(hashes.len() as u64, Ordering::Relaxed);

                // Check patterns inline (no separate thread)
                for (secret_key, hash) in secret_keys.iter().zip(hashes.iter()) {
                    // Convert hash to address
                    // The GPU already computed Keccak-256, so we just need to:
                    // 1. Take last 20 bytes of hash
                    // 2. Prepend 0x41 (Tron version byte)
                    // 3. Base58 encode with checksum
                    let mut address_bytes = [0u8; 21];
                    address_bytes[0] = 0x41; // Tron prefix
                    address_bytes[1..21].copy_from_slice(&hash[12..32]); // Last 20 bytes

                    let address = raw_address_to_base58(&address_bytes);

                    // Check if it matches the pattern
                    if searcher.matches(&address) {
                        let found = FoundAddress {
                            address,
                            private_key: private_key_to_hex(secret_key),
                        };

                        // Send match (if send fails, channel is closed, so exit)
                        if sender.send(found).is_err() {
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("GPU hashing error: {}", e);
                // Continue processing despite error
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_gpu_search_initialization() {
        // Test that GPU search can be initialized
        if super::super::is_gpu_available() {
            let config = VanityConfig::prefix_only("A".to_string(), false);
            let (tx, _rx) = mpsc::channel();
            let running = Arc::new(AtomicBool::new(true));
            let attempts = Arc::new(AtomicU64::new(0));

            let result = search_continuous_gpu(config, 2, tx, running.clone(), attempts);

            // Should successfully initialize
            assert!(result.is_ok(), "GPU search initialization failed: {:?}", result);

            // Let it run briefly
            thread::sleep(Duration::from_millis(100));

            // Stop it
            running.store(false, Ordering::Relaxed);
        } else {
            println!("GPU not available, skipping test");
        }
    }
}

/// Integration test to verify GPU and CPU produce identical Keccak-256 hashes
///
/// This test ensures the Metal GPU implementation matches the CPU tiny-keccak implementation

use tron_vanity_generator::{generate_keypair_direct, is_gpu_available, initialize};
use tron_vanity_generator::gpu::pipeline::GpuHasher;
use secp256k1::PublicKey;
use tiny_keccak::{Hasher, Keccak};

fn cpu_keccak256(public_key: &PublicKey) -> [u8; 32] {
    let public_key_bytes = public_key.serialize_uncompressed();
    let mut keccak = Keccak::v256();
    keccak.update(&public_key_bytes[1..]); // Skip 0x04 prefix
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);
    hash
}

#[test]
fn test_gpu_cpu_consistency() {
    // Skip test if GPU not available
    if !is_gpu_available() {
        println!("GPU not available, skipping consistency test");
        return;
    }

    // Initialize GPU
    let context = initialize().expect("Failed to initialize GPU context");
    let hasher = GpuHasher::new(context).expect("Failed to create GPU hasher");

    // Generate test keypairs
    let mut test_keys = Vec::new();
    let mut cpu_hashes = Vec::new();
    let mut gpu_inputs = Vec::new();

    for _ in 0..100 {
        let (_, public_key) = generate_keypair_direct();

        // CPU hash
        let cpu_hash = cpu_keccak256(&public_key);
        cpu_hashes.push(cpu_hash);

        // Prepare GPU input (64 bytes without 0x04 prefix)
        let public_key_bytes = public_key.serialize_uncompressed();
        let mut input = [0u8; 64];
        input.copy_from_slice(&public_key_bytes[1..]);
        gpu_inputs.push(input);

        test_keys.push(public_key);
    }

    // GPU batch hash
    let gpu_hashes = hasher.hash_batch(&gpu_inputs).expect("GPU hashing failed");

    // Compare results
    assert_eq!(cpu_hashes.len(), gpu_hashes.len());

    let mut matches = 0;
    let mut mismatches = 0;

    for i in 0..cpu_hashes.len() {
        if cpu_hashes[i] == gpu_hashes[i] {
            matches += 1;
        } else {
            mismatches += 1;
            println!("Mismatch at index {}:", i);
            println!("  CPU: {}", hex::encode(&cpu_hashes[i]));
            println!("  GPU: {}", hex::encode(&gpu_hashes[i]));
        }
    }

    println!("\nConsistency Test Results:");
    println!("  Total: {}", cpu_hashes.len());
    println!("  Matches: {}", matches);
    println!("  Mismatches: {}", mismatches);

    // All should match
    assert_eq!(mismatches, 0, "GPU and CPU implementations produced different hashes");
    println!("\n✅ GPU and CPU implementations are consistent!");
}

#[test]
fn test_gpu_single_hash_correctness() {
    if !is_gpu_available() {
        println!("GPU not available, skipping test");
        return;
    }

    let context = initialize().expect("Failed to initialize GPU");
    let hasher = GpuHasher::new(context).expect("Failed to create GPU hasher");

    // Test with known input
    let (_, public_key) = generate_keypair_direct();

    // CPU hash
    let cpu_hash = cpu_keccak256(&public_key);

    // GPU hash
    let public_key_bytes = public_key.serialize_uncompressed();
    let mut input = [0u8; 64];
    input.copy_from_slice(&public_key_bytes[1..]);

    let gpu_hashes = hasher.hash_batch(&[input]).expect("GPU hashing failed");

    assert_eq!(gpu_hashes.len(), 1);
    assert_eq!(cpu_hash, gpu_hashes[0], "Single hash mismatch");

    println!("✅ Single hash test passed");
}

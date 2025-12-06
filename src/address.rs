use secp256k1::{SecretKey, PublicKey, Scalar, SECP256K1};
use tiny_keccak::{Hasher, Keccak};
use sha2::{Sha256, Digest};
use rand::{Rng, RngCore};

/// Generate a random secp256k1 keypair using the global context
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    SECP256K1.generate_keypair(&mut rand::thread_rng())
}

/// Generate a keypair directly from random bytes (fastest method)
/// This is the preferred method for vanity address generation
/// Uses the global secp256k1 context for maximum performance
#[inline(always)]
pub fn generate_keypair_direct() -> (SecretKey, PublicKey) {
    let mut rng = rand::thread_rng();
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            let pk = PublicKey::from_secret_key(&SECP256K1, &sk);
            return (sk, pk);
        }
    }
}

/// Generate a keypair from a seed (used for optimized batch generation)
/// Note: generate_keypair_direct() is faster and preferred for most use cases
pub fn generate_keypair_from_seed(seed: u64) -> (SecretKey, PublicKey) {
    // Create deterministic but unique secret key from seed
    let mut secret_bytes = [0u8; 32];
    secret_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    secret_bytes[8..16].copy_from_slice(&seed.to_be_bytes());

    // Mix it with random data to ensure unpredictability
    let mut rng = rand::thread_rng();
    for i in 16..32 {
        secret_bytes[i] = rng.gen();
    }

    // Hash to get valid secret key
    let mut hasher = Sha256::new();
    hasher.update(&secret_bytes);
    let hash = hasher.finalize();

    let secret_key = SecretKey::from_slice(&hash)
        .expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&SECP256K1, &secret_key);

    (secret_key, public_key)
}

/// Double SHA-256 hash (used for checksum)
#[inline(always)]
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Get raw 21-byte address (before Base58 encoding)
/// This is step 1-4 of the address generation process, before the expensive Base58 encoding
#[inline(always)]
pub fn public_key_to_raw_address(public_key: &PublicKey) -> [u8; 21] {
    let public_key_bytes = public_key.serialize_uncompressed();

    let mut keccak = Keccak::v256();
    keccak.update(&public_key_bytes[1..]);
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);

    let mut address_bytes = [0u8; 21];
    address_bytes[0] = 0x41;
    address_bytes[1..21].copy_from_slice(&hash[12..32]);
    address_bytes
}

/// Convert raw address bytes to Base58 string (with checksum)
/// This is step 5-6 of the address generation process
#[inline(always)]
pub fn raw_address_to_base58(address_bytes: &[u8; 21]) -> String {
    let checksum = double_sha256(address_bytes);
    let mut full = [0u8; 25];
    full[..21].copy_from_slice(address_bytes);
    full[21..25].copy_from_slice(&checksum[..4]);
    bs58::encode(full).into_string()
}

/// Get full 25-byte address with checksum (for range checking)
/// This skips the expensive Base58 encoding
#[inline(always)]
pub fn public_key_to_raw_address_with_checksum(public_key: &PublicKey) -> [u8; 25] {
    let address_bytes = public_key_to_raw_address(public_key);
    let checksum = double_sha256(&address_bytes);
    let mut full = [0u8; 25];
    full[..21].copy_from_slice(&address_bytes);
    full[21..25].copy_from_slice(&checksum[..4]);
    full
}

/// Convert raw 25-byte address (with checksum) to Base58 string
/// This is an optimized variant that skips checksum calculation
#[inline(always)]
pub fn raw_address_to_base58_from_full(full: &[u8; 25]) -> String {
    bs58::encode(full).into_string()
}

/// Convert a public key to a Tron address
///
/// The process:
/// 1. Take uncompressed public key (65 bytes, skip first byte 0x04)
/// 2. Keccak-256 hash the remaining 64 bytes
/// 3. Take last 20 bytes of the hash
/// 4. Prepend 0x41 (Tron version byte)
/// 5. Calculate checksum (double SHA-256, take first 4 bytes)
/// 6. Append checksum and Base58 encode
pub fn public_key_to_tron_address(public_key: &PublicKey) -> String {
    let address_bytes = public_key_to_raw_address(public_key);
    raw_address_to_base58(&address_bytes)
}

/// Convert a secret key to hex string
pub fn private_key_to_hex(secret_key: &SecretKey) -> String {
    hex::encode(secret_key.secret_bytes())
}

/// Sequential keypair generator - MUCH faster than random generation!
///
/// Instead of generating a random private key for every attempt (which requires
/// expensive scalar multiplication k × G), this generator:
/// 1. Starts with one random keypair (k, P) where P = k × G
/// 2. For each subsequent key, performs point addition: P_next = P_prev + G
/// 3. Increments the private key: k_next = k_prev + 1
///
/// Point addition is ~100x faster than scalar multiplication!
pub struct SequentialGenerator {
    current_secret: SecretKey,
    current_public: PublicKey,
    one: Scalar, // Pre-computed scalar for incrementing
}

impl SequentialGenerator {
    /// Create a new sequential generator starting from a random point
    #[inline(always)]
    pub fn new() -> Self {
        let (secret, public) = generate_keypair_direct();

        // Pre-compute scalar "1" for maximum performance
        let one = Scalar::from_be_bytes([
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        ]).expect("scalar 1 is valid");

        Self {
            current_secret: secret,
            current_public: public,
            one,
        }
    }

    /// Get the next keypair in sequence
    /// This uses FAST point addition instead of SLOW scalar multiplication
    #[inline(always)]
    pub fn next(&mut self) -> (&SecretKey, &PublicKey) {
        // FAST: Add G to current public key (point addition)
        // This is the key optimization - ~100x faster than scalar multiplication!
        self.current_public = self.current_public
            .add_exp_tweak(&SECP256K1, &self.one)
            .expect("valid point addition");

        // FAST: Increment secret key by 1 (scalar addition)
        self.current_secret = self.current_secret
            .add_tweak(&self.one)
            .expect("valid scalar addition");

        (&self.current_secret, &self.current_public)
    }

    /// Get current keypair without advancing
    #[inline(always)]
    pub fn current(&self) -> (&SecretKey, &PublicKey) {
        (&self.current_secret, &self.current_public)
    }
}

impl Default for SequentialGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_generation() {
        let (secret_key, public_key) = generate_keypair();
        let address = public_key_to_tron_address(&public_key);

        // Tron addresses start with 'T' and are 34 characters long
        assert!(address.starts_with('T'));
        assert_eq!(address.len(), 34);

        // Private key should be 64 hex characters
        let private_hex = private_key_to_hex(&secret_key);
        assert_eq!(private_hex.len(), 64);
    }

    #[test]
    fn test_deterministic_generation() {
        let (_, pub1) = generate_keypair_from_seed(12345);
        let (_, pub2) = generate_keypair_from_seed(12346);

        let addr1 = public_key_to_tron_address(&pub1);
        let addr2 = public_key_to_tron_address(&pub2);

        // Different seeds should produce different addresses
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_sequential_generator() {
        let mut gen = SequentialGenerator::new();

        // Get first address
        let addr1 = {
            let (sk, pk) = gen.current();
            let addr = public_key_to_tron_address(pk);
            let private_hex = private_key_to_hex(sk);
            assert_eq!(private_hex.len(), 64);
            addr
        };

        // Get next address
        let addr2 = {
            let (sk, pk) = gen.next();
            let addr = public_key_to_tron_address(pk);
            let private_hex = private_key_to_hex(sk);
            assert_eq!(private_hex.len(), 64);
            addr
        };

        // Addresses should be different
        assert_ne!(addr1, addr2);

        // Generate a few more to ensure it keeps working
        for _ in 0..100 {
            let (sk, pk) = gen.next();
            let addr = public_key_to_tron_address(pk);

            // Should always start with 'T' and be 34 chars
            assert!(addr.starts_with('T'));
            assert_eq!(addr.len(), 34);

            // Private key should be valid
            let private_hex = private_key_to_hex(sk);
            assert_eq!(private_hex.len(), 64);
        }
    }

    #[test]
    fn test_sequential_generator_produces_valid_addresses() {
        let mut gen = SequentialGenerator::new();

        // Generate 1000 addresses and verify they're all valid
        for _ in 0..1000 {
            let (sk, pk) = gen.next();
            let addr = public_key_to_tron_address(pk);

            // Verify address format
            assert!(addr.starts_with('T'));
            assert_eq!(addr.len(), 34);

            // Verify we can derive the same public key from the secret key
            let derived_pk = PublicKey::from_secret_key(&SECP256K1, sk);
            assert_eq!(pk.serialize(), derived_pk.serialize());
        }
    }
}

#[test]
fn test_known_vector() {
    // Official test vector from TronWeb docs
    let private_key_hex = "3481E79956D4BD95F358AC96D151C976392FC4E3FC132F78A847906DE588C145";
    let expected_address = "TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL";
    
    let private_bytes = hex::decode(private_key_hex).unwrap();
    let secret_key = SecretKey::from_slice(&private_bytes).unwrap();
    let public_key = PublicKey::from_secret_key(&SECP256K1, &secret_key);
    let address = public_key_to_tron_address(&public_key);
    
    println!("Generated: {}", address);
    println!("Expected:  {}", expected_address);
    assert_eq!(address, expected_address);
}

use crate::address::{
    private_key_to_hex, public_key_to_tron_address,
    public_key_to_raw_address_with_checksum, raw_address_to_base58_from_full,
    SequentialGenerator,
};
use crate::range_check::PrefixRange;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::mpsc;

/// Result of a successful vanity address search
#[derive(Debug, Clone)]
pub struct VanityResult {
    pub private_key: String,
    pub address: String,
    pub attempts: u64,
}

/// A found address for continuous search mode
#[derive(Debug, Clone)]
pub struct FoundAddress {
    pub address: String,
    pub private_key: String,
}

/// Configuration for vanity address search
#[derive(Debug, Clone)]
pub struct VanityConfig {
    pub prefix: Option<String>,
    pub suffix: Option<String>,
    pub case_sensitive: bool,
}

impl VanityConfig {
    /// Create a new configuration
    pub fn new(prefix: Option<String>, suffix: Option<String>, case_sensitive: bool) -> Self {
        Self {
            prefix,
            suffix,
            case_sensitive,
        }
    }

    /// Create config for prefix-only search (backward compatibility)
    pub fn prefix_only(pattern: String, case_sensitive: bool) -> Self {
        Self {
            prefix: Some(pattern),
            suffix: None,
            case_sensitive,
        }
    }

    /// Create config for suffix-only search (backward compatibility)
    pub fn suffix_only(pattern: String, case_sensitive: bool) -> Self {
        Self {
            prefix: None,
            suffix: Some(pattern),
            case_sensitive,
        }
    }

    /// Create a human-readable description of the pattern
    /// Shows the full address format including the leading 'T'
    pub fn pattern_description(&self) -> String {
        match (&self.prefix, &self.suffix) {
            (Some(p), Some(s)) => format!("T{}...{} (prefix + suffix)", p, s),
            (Some(p), None) => format!("T{}... (prefix)", p),
            (None, Some(s)) => format!("T...{} (suffix)", s),
            (None, None) => "None".to_string(),
        }
    }
}

/// Vanity address searcher configuration
pub struct VanitySearcher {
    pub config: VanityConfig,
    // Pre-computed uppercase patterns for fast case-insensitive matching
    prefix_upper: Option<String>,
    suffix_upper: Option<String>,
    // Pre-computed range for fast prefix matching
    prefix_range: Option<PrefixRange>,
}

impl VanitySearcher {
    /// Create a new vanity searcher with a config
    pub fn new(config: VanityConfig) -> Self {
        // Pre-compute uppercase patterns to avoid repeated allocations in hot loop
        let prefix_upper = config.prefix.as_ref().map(|p| p.to_uppercase());
        let suffix_upper = config.suffix.as_ref().map(|s| s.to_uppercase());

        // Pre-compute range for prefix matching (case-sensitive only for now)
        let prefix_range = if config.case_sensitive {
            config.prefix.as_ref().map(|p| PrefixRange::from_prefix(p))
        } else {
            None
        };

        Self {
            config,
            prefix_upper,
            suffix_upper,
            prefix_range,
        }
    }

    /// Create searcher from old-style parameters (backward compatibility)
    pub fn from_pattern(pattern: String, case_sensitive: bool, suffix_mode: bool) -> Self {
        let config = if suffix_mode {
            VanityConfig::suffix_only(pattern, case_sensitive)
        } else {
            VanityConfig::prefix_only(pattern, case_sensitive)
        };
        Self::new(config)
    }

    /// Check if an address matches the pattern
    /// Optimized with early exit and pre-computed patterns
    pub fn matches(&self, address: &str) -> bool {
        // Tron addresses always start with 'T', so skip it
        let addr = &address[1..];

        // Check prefix match with early exit
        let prefix_ok = match (&self.config.prefix, &self.prefix_upper) {
            (Some(p), _) if self.config.case_sensitive => addr.starts_with(p),
            (_, Some(pu)) => addr.to_ascii_uppercase().starts_with(pu),
            _ => true,
        };

        // Early exit if prefix doesn't match
        if !prefix_ok {
            return false;
        }

        // Check suffix match
        let suffix_ok = match (&self.config.suffix, &self.suffix_upper) {
            (Some(s), _) if self.config.case_sensitive => addr.ends_with(s),
            (_, Some(su)) => addr.to_ascii_uppercase().ends_with(su),
            _ => true,
        };

        suffix_ok
    }
}

/// Search for a vanity address in parallel (backward compatibility)
///
/// Uses Rayon for parallel iteration across all available CPU cores.
/// Employs batch-based RNG optimization for improved performance.
pub fn search_parallel(
    pattern: &str,
    case_sensitive: bool,
    suffix_mode: bool,
    num_threads: usize,
) -> Option<VanityResult> {
    let config = if suffix_mode {
        VanityConfig::suffix_only(pattern.to_string(), case_sensitive)
    } else {
        VanityConfig::prefix_only(pattern.to_string(), case_sensitive)
    };
    search_with_config(config, num_threads)
}

/// Search for a vanity address with a configuration
///
/// This is the preferred API for new code, supporting combined prefix+suffix search.
pub fn search_with_config(config: VanityConfig, num_threads: usize) -> Option<VanityResult> {
    let searcher = VanitySearcher::new(config);
    let found = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));

    // Configure rayon thread pool
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .expect("Failed to build thread pool");

    // Search in parallel using chunks for better performance
    let result = pool.install(|| {
        (0..num_threads).into_par_iter()
            .find_map_any(|thread_id| {
                search_worker(&searcher, &found, &attempts, thread_id as u64)
            })
    });

    result
}

/// Worker function for parallel search
/// Each worker searches independently until a match is found
fn search_worker(
    searcher: &VanitySearcher,
    found: &Arc<AtomicBool>,
    attempts: &Arc<AtomicU64>,
    _thread_id: u64,
) -> Option<VanityResult> {
    const BATCH_SIZE: u64 = 50_000; // Batch size for atomic updates
    let mut local_attempts = 0u64;

    // OPTIMIZATION: Use sequential generation instead of random!
    // This replaces expensive scalar multiplication with fast point addition
    let mut generator = SequentialGenerator::new();

    loop {
        // Check if another thread found a match
        if found.load(Ordering::Relaxed) {
            return None;
        }

        for _ in 0..BATCH_SIZE {
            // FAST: Point addition instead of scalar multiplication!
            let (secret_key, public_key) = generator.next();
            local_attempts += 1;

            // Fast path: range check before expensive Base58 encoding
            if let Some(ref range) = searcher.prefix_range {
                let raw_addr = public_key_to_raw_address_with_checksum(&public_key);

                // Quick byte comparison - most addresses fail here
                if !range.matches(&raw_addr) {
                    continue; // Skip expensive Base58 encoding
                }

                // Potential match! Do full Base58 encoding
                let address = raw_address_to_base58_from_full(&raw_addr);

                // Final verification with full pattern matching
                if searcher.matches(&address) {
                    // Found a match!
                    found.store(true, Ordering::Relaxed);
                    attempts.fetch_add(local_attempts, Ordering::Relaxed);

                    return Some(VanityResult {
                        private_key: private_key_to_hex(&secret_key),
                        address,
                        attempts: attempts.load(Ordering::Relaxed),
                    });
                }
            } else {
                // Fallback: original path for case-insensitive or suffix searches
                let address = public_key_to_tron_address(&public_key);

                if searcher.matches(&address) {
                    // Found a match!
                    found.store(true, Ordering::Relaxed);
                    attempts.fetch_add(local_attempts, Ordering::Relaxed);

                    return Some(VanityResult {
                        private_key: private_key_to_hex(&secret_key),
                        address,
                        attempts: attempts.load(Ordering::Relaxed),
                    });
                }
            }
        }

        // Update global counter every batch
        attempts.fetch_add(BATCH_SIZE, Ordering::Relaxed);
    }
}

/// Get the current attempt count (useful for progress monitoring)
pub fn get_attempts(attempts: &Arc<AtomicU64>) -> u64 {
    attempts.load(Ordering::Relaxed)
}

/// Continuous search mode - searches forever and sends found addresses through channel
///
/// This function spawns worker threads that continuously search for matching addresses.
/// When a match is found, it's sent through the channel but search continues.
/// Workers will run until the running flag is set to false.
pub fn search_continuous(
    config: VanityConfig,
    num_threads: usize,
    sender: mpsc::Sender<FoundAddress>,
    running: Arc<AtomicBool>,
    attempts: Arc<AtomicU64>,
) {
    let searcher = Arc::new(VanitySearcher::new(config));

    // Spawn worker threads
    for thread_id in 0..num_threads {
        let sender = sender.clone();
        let running = running.clone();
        let attempts = attempts.clone();
        let searcher = searcher.clone();

        std::thread::spawn(move || {
            continuous_worker(&searcher, &sender, &running, &attempts, thread_id as u64);
        });
    }
}

/// Worker function for continuous search
/// Searches indefinitely, sending all matches through the channel
fn continuous_worker(
    searcher: &VanitySearcher,
    sender: &mpsc::Sender<FoundAddress>,
    running: &Arc<AtomicBool>,
    attempts: &Arc<AtomicU64>,
    _thread_id: u64,
) {
    const BATCH_SIZE: u64 = 50_000; // Batch size for atomic updates

    // OPTIMIZATION: Use sequential generation instead of random!
    // This replaces expensive scalar multiplication with fast point addition
    let mut generator = SequentialGenerator::new();

    while running.load(Ordering::Relaxed) {
        for _ in 0..BATCH_SIZE {
            // FAST: Point addition instead of scalar multiplication!
            let (secret_key, public_key) = generator.next();

            // Fast path: range check before expensive Base58 encoding
            if let Some(ref range) = searcher.prefix_range {
                let raw_addr = public_key_to_raw_address_with_checksum(&public_key);

                // Quick byte comparison - most addresses fail here
                if !range.matches(&raw_addr) {
                    continue; // Skip expensive Base58 encoding
                }

                // Potential match! Do full Base58 encoding
                let address = raw_address_to_base58_from_full(&raw_addr);

                // Final verification with full pattern matching
                if searcher.matches(&address) {
                    // Found a match! Send it through the channel but keep searching
                    let found = FoundAddress {
                        address,
                        private_key: private_key_to_hex(&secret_key),
                    };

                    // If send fails (channel closed), stop the worker
                    if sender.send(found).is_err() {
                        return;
                    }
                }
            } else {
                // Fallback: original path for case-insensitive or suffix searches
                let address = public_key_to_tron_address(&public_key);

                if searcher.matches(&address) {
                    // Found a match! Send it through the channel but keep searching
                    let found = FoundAddress {
                        address,
                        private_key: private_key_to_hex(&secret_key),
                    };

                    // If send fails (channel closed), stop the worker
                    if sender.send(found).is_err() {
                        return;
                    }
                }
            }
        }

        // Update global counter every batch
        attempts.fetch_add(BATCH_SIZE, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        let searcher = VanitySearcher::from_pattern("ABC".to_string(), true, false);
        assert!(searcher.matches("TABC123456789012345678901234567890"));
        assert!(!searcher.matches("TXBC123456789012345678901234567890"));
    }

    #[test]
    fn test_case_insensitive_matching() {
        let searcher = VanitySearcher::from_pattern("abc".to_string(), false, false);
        assert!(searcher.matches("TABC123456789012345678901234567890"));
        assert!(searcher.matches("Tabc123456789012345678901234567890"));
    }

    #[test]
    fn test_suffix_matching() {
        let searcher = VanitySearcher::from_pattern("XYZ".to_string(), true, true);
        assert!(searcher.matches("T123456789012345678901234567890XYZ"));
        assert!(!searcher.matches("TXYZ123456789012345678901234567890"));
    }

    #[test]
    fn test_combined_prefix_suffix() {
        let config = VanityConfig::new(Some("AB".to_string()), Some("YZ".to_string()), true);
        let searcher = VanitySearcher::new(config);

        // Should match both prefix and suffix
        assert!(searcher.matches("TAB12345678901234567890123456YZ"));

        // Should not match - wrong prefix
        assert!(!searcher.matches("TXB12345678901234567890123456YZ"));

        // Should not match - wrong suffix
        assert!(!searcher.matches("TAB12345678901234567890123456XZ"));
    }

    #[test]
    fn test_combined_case_insensitive() {
        let config = VanityConfig::new(Some("ab".to_string()), Some("yz".to_string()), false);
        let searcher = VanitySearcher::new(config);

        // Should match case-insensitively
        assert!(searcher.matches("TAB12345678901234567890123456YZ"));
        assert!(searcher.matches("Tab12345678901234567890123456yz"));
    }

    #[test]
    fn test_simple_search() {
        // Search for a single character (should be fast)
        let result = search_parallel("A", false, false, 2);
        assert!(result.is_some());

        if let Some(vanity_result) = result {
            assert!(vanity_result.address.to_uppercase().contains("TA"));
            assert_eq!(vanity_result.private_key.len(), 64);
        }
    }
}

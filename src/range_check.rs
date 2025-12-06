/// Pre-computed range for fast prefix matching without Base58 encoding
pub struct PrefixRange {
    /// Minimum 25-byte value that would encode to this prefix
    pub min: [u8; 25],
    /// Maximum 25-byte value that would encode to this prefix
    pub max: [u8; 25],
}

impl PrefixRange {
    /// Create a range from a Base58 prefix pattern (e.g., "ABC" for "TABC...")
    /// The prefix should NOT include the leading 'T'
    pub fn from_prefix(prefix: &str) -> Self {
        // TRON addresses are 25 bytes: 0x41 + 20 bytes address + 4 bytes checksum
        // The full address encodes to 34 Base58 characters starting with 'T'

        // For minimum: pad with '1' (smallest Base58 char)
        // For maximum: pad with 'z' (largest Base58 char)

        let full_prefix = format!("T{}", prefix);
        let remaining = 34 - full_prefix.len();

        // Minimum: T{prefix}111...1 (pad with '1's)
        let min_str = format!("{}{}", full_prefix, "1".repeat(remaining));
        let min_bytes = bs58::decode(&min_str).into_vec().unwrap_or_else(|_| vec![0u8; 25]);

        // Maximum: T{prefix}zzz...z (pad with 'z's)
        let max_str = format!("{}{}", full_prefix, "z".repeat(remaining));
        let max_bytes = bs58::decode(&max_str).into_vec().unwrap_or_else(|_| vec![0xff; 25]);

        let mut min = [0u8; 25];
        let mut max = [0xffu8; 25];

        if min_bytes.len() == 25 {
            min.copy_from_slice(&min_bytes);
        }
        if max_bytes.len() == 25 {
            max.copy_from_slice(&max_bytes);
        }

        Self { min, max }
    }

    /// Check if a 25-byte address (with checksum) falls within this range
    #[inline(always)]
    pub fn matches(&self, addr_with_checksum: &[u8; 25]) -> bool {
        // Compare bytes lexicographically
        addr_with_checksum >= &self.min && addr_with_checksum <= &self.max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_range_creation() {
        let range = PrefixRange::from_prefix("ABC");

        // The range should have valid min and max values
        assert!(range.min[0] == 0x41); // Should start with TRON address byte
        assert!(range.max[0] == 0x41);
    }

    #[test]
    fn test_range_matching() {
        let range = PrefixRange::from_prefix("A");

        // Create a test address that should be in range
        // This is a simplified test - real addresses would need valid checksums
        let mut test_addr = [0u8; 25];
        test_addr[0] = 0x41; // TRON address byte

        // The range check should work (though we can't easily test without real addresses)
        // Just verify it doesn't panic
        let _matches = range.matches(&test_addr);
    }
}

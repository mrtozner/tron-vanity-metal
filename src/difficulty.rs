use std::time::Duration;

/// Calculate difficulty based on prefix/suffix patterns
/// Base58 has 58 characters (case sensitive) or ~34 (case insensitive)
pub fn calculate_difficulty(prefix: Option<&str>, suffix: Option<&str>, case_sensitive: bool) -> u64 {
    let base: u64 = if case_sensitive { 58 } else { 34 };

    let prefix_diff = prefix.map(|p| base.saturating_pow(p.len() as u32)).unwrap_or(1);
    let suffix_diff = suffix.map(|s| base.saturating_pow(s.len() as u32)).unwrap_or(1);

    prefix_diff.saturating_mul(suffix_diff)
}

/// Estimate time based on difficulty and speed
pub fn estimate_time(difficulty: u64, keys_per_sec: u64) -> Duration {
    if keys_per_sec == 0 {
        return Duration::from_secs(u64::MAX);
    }
    Duration::from_secs(difficulty / keys_per_sec)
}

/// Format difficulty number as "38.07B", "195.11K", etc.
pub fn format_difficulty(n: u64) -> String {
    if n >= 1_000_000_000_000 {
        format!("{:.2}T", n as f64 / 1_000_000_000_000.0)
    } else if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.2}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Format duration as "5.3 hours", "2.5 minutes", "45 seconds", etc.
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();

    if secs >= 86400 {
        format!("{:.1} days", secs as f64 / 86400.0)
    } else if secs >= 3600 {
        format!("{:.1} hours", secs as f64 / 3600.0)
    } else if secs >= 60 {
        format!("{:.1} minutes", secs as f64 / 60.0)
    } else {
        format!("{} seconds", secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_calculation() {
        // Single prefix
        let diff = calculate_difficulty(Some("ABC"), None, true);
        assert_eq!(diff, 58u64.pow(3)); // 195,112

        // Single suffix
        let diff = calculate_difficulty(None, Some("777"), true);
        assert_eq!(diff, 58u64.pow(3));

        // Combined
        let diff = calculate_difficulty(Some("AB"), Some("77"), true);
        assert_eq!(diff, 58u64.pow(2) * 58u64.pow(2));

        // Case insensitive
        let diff = calculate_difficulty(Some("AB"), None, false);
        assert_eq!(diff, 34u64.pow(2));
    }

    #[test]
    fn test_format_difficulty() {
        assert_eq!(format_difficulty(500), "500");
        assert_eq!(format_difficulty(5000), "5.00K");
        assert_eq!(format_difficulty(5_000_000), "5.00M");
        assert_eq!(format_difficulty(5_000_000_000), "5.00B");
        assert_eq!(format_difficulty(5_000_000_000_000), "5.00T");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30 seconds");
        assert_eq!(format_duration(Duration::from_secs(90)), "1.5 minutes");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1.0 hours");
        assert_eq!(format_duration(Duration::from_secs(90000)), "1.0 days");
    }

    #[test]
    fn test_estimate_time() {
        let time = estimate_time(1_000_000, 100_000);
        assert_eq!(time.as_secs(), 10);

        // Handle zero speed
        let time = estimate_time(1_000_000, 0);
        assert_eq!(time.as_secs(), u64::MAX);
    }
}

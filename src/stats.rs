use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub struct SearchStats {
    pub attempts: AtomicU64,
    pub start_time: Instant,
}

impl SearchStats {
    pub fn new() -> Self {
        Self {
            attempts: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Get current attempt count
    pub fn get_attempts(&self) -> u64 {
        self.attempts.load(Ordering::Relaxed)
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Calculate current speed (keys/sec)
    pub fn speed(&self) -> f64 {
        let attempts = self.get_attempts() as f64;
        let elapsed = self.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            attempts / elapsed
        } else {
            0.0
        }
    }

    /// Get rate as u64 (keys/sec)
    pub fn get_rate(&self) -> u64 {
        self.speed() as u64
    }

    /// Calculate luck factor (how lucky was the find?)
    /// < 1.0 = unlucky (took longer than expected)
    /// > 1.0 = lucky (found faster than expected)
    pub fn luck_factor(&self, expected_attempts: u64) -> f64 {
        if expected_attempts == 0 {
            return 1.0;
        }
        expected_attempts as f64 / self.get_attempts() as f64
    }

    /// Format speed with units
    pub fn format_speed(&self) -> String {
        let speed = self.speed();
        if speed >= 1_000_000.0 {
            format!("{:.2}M keys/sec", speed / 1_000_000.0)
        } else if speed >= 1_000.0 {
            format!("{:.2}K keys/sec", speed / 1_000.0)
        } else {
            format!("{:.0} keys/sec", speed)
        }
    }
}

impl Default for SearchStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Format a number with comma separators
pub fn format_number(n: u64) -> String {
    n.to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap()
        .join(",")
}

/// Format speed in human-readable form
pub fn format_speed(speed: u64) -> String {
    if speed >= 1_000_000 {
        format!("{:.2}M", speed as f64 / 1_000_000.0)
    } else if speed >= 1_000 {
        format!("{:.2}K", speed as f64 / 1_000.0)
    } else {
        format!("{}", speed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_search_stats() {
        let stats = SearchStats::new();

        // Test initial state
        assert_eq!(stats.get_attempts(), 0);
        assert!(stats.elapsed().as_secs() < 1);

        // Simulate some attempts
        stats.attempts.store(1000, Ordering::Relaxed);
        assert_eq!(stats.get_attempts(), 1000);
    }

    #[test]
    fn test_luck_factor() {
        let stats = SearchStats::new();
        stats.attempts.store(50, Ordering::Relaxed);

        // If expected 100 but got in 50, luck factor = 2.0 (2x lucky)
        let luck = stats.luck_factor(100);
        assert_eq!(luck, 2.0);

        // Handle zero expected
        let luck = stats.luck_factor(0);
        assert_eq!(luck, 1.0);
    }

    #[test]
    fn test_format_speed() {
        let stats = SearchStats::new();
        thread::sleep(Duration::from_millis(10));
        stats.attempts.store(1_000_000, Ordering::Relaxed);

        let formatted = stats.format_speed();
        assert!(formatted.contains("keys/sec"));
    }
}

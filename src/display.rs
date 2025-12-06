use indicatif::{ProgressBar, ProgressStyle};
use crate::search::VanityResult;
use crate::stats::SearchStats;
use crate::difficulty::{format_difficulty, format_duration};

/// Create enhanced progress bar
pub fn create_progress_bar(pattern_desc: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap()
    );
    pb.set_message(format!("Searching for: {}", pattern_desc));
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb
}

/// Update progress bar with current stats
pub fn update_progress(pb: &ProgressBar, stats: &SearchStats, difficulty: u64) {
    let attempts = stats.get_attempts();
    let speed = stats.speed();
    let progress_pct = (attempts as f64 / difficulty as f64 * 100.0).min(99.9);

    let eta = if speed > 0.0 {
        let remaining = difficulty.saturating_sub(attempts);
        let eta_secs = remaining as f64 / speed;
        format_duration(std::time::Duration::from_secs_f64(eta_secs))
    } else {
        "calculating...".to_string()
    };

    pb.set_message(format!(
        "Speed: {} | Scanned: {} | Progress: {:.1}% | ETA: {}",
        format_speed(speed),
        format_number(attempts),
        progress_pct,
        eta
    ));
}

/// Display enhanced success message
pub fn display_success_enhanced(
    result: &VanityResult,
    stats: &SearchStats,
    difficulty: u64,
    pattern_desc: &str,
) {
    let luck = stats.luck_factor(difficulty);

    println!("\n✓ Found vanity address!");
    println!("========================");
    println!("Address:      {}", result.address);
    println!("Private Key:  {}", result.private_key);
    println!("Pattern:      {}", pattern_desc);
    println!();
    println!("Statistics:");
    println!("  Wallets scanned:  {}", format_number(stats.get_attempts()));
    println!("  Time elapsed:     {}", format_duration(stats.elapsed()));
    println!("  Average speed:    {}", stats.format_speed());
    println!("  Difficulty:       1 in {}", format_difficulty(difficulty));

    if luck > 1.2 {
        println!("  Luck factor:      {:.2}x (found faster than expected!)", luck);
    } else if luck < 0.8 {
        println!("  Luck factor:      {:.2}x (took longer than expected)", luck);
    } else {
        println!("  Luck factor:      {:.2}x (about average)", luck);
    }
}

fn format_speed(speed: f64) -> String {
    if speed >= 1_000_000.0 {
        format!("{:.2}M keys/sec", speed / 1_000_000.0)
    } else if speed >= 1_000.0 {
        format!("{:.2}K keys/sec", speed / 1_000.0)
    } else {
        format!("{:.0} keys/sec", speed)
    }
}

fn format_number(n: u64) -> String {
    n.to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_speed() {
        assert_eq!(format_speed(500.0), "500 keys/sec");
        assert_eq!(format_speed(5_000.0), "5.00K keys/sec");
        assert_eq!(format_speed(2_500_000.0), "2.50M keys/sec");
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(123), "123");
        assert_eq!(format_number(1234), "1,234");
        assert_eq!(format_number(1234567), "1,234,567");
        assert_eq!(format_number(1234567890), "1,234,567,890");
    }
}

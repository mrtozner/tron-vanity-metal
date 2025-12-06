use clap::Parser;
use std::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::io::Write;
use tron_vanity_generator::{
    search_continuous, VanityConfig, FoundAddress,
    format_duration,
    display_hardware_info, format_number, format_speed,
    public_key_to_tron_address, SequentialGenerator,
    is_gpu_available, search_continuous_gpu,
};

#[derive(Parser)]
#[command(name = "tron-vanity-generator")]
#[command(about = "High-performance Tron vanity address generator optimized for Apple Silicon", long_about = None)]
struct Cli {
    /// Vanity pattern to search for (default: prefix mode for backward compatibility)
    /// Use -p or -e flags for explicit prefix/suffix specification
    #[arg(value_name = "PATTERN", default_value = "")]
    pattern: String,

    /// Prefix pattern (characters after the leading 'T')
    /// Example: 'R5' finds 'TR5...', 'ABC' finds 'TABC...'
    #[arg(short = 'p', long = "prefix", value_name = "PREFIX", help = "Prefix after 'T' (e.g., 'R5' finds 'TR5...')")]
    prefix: Option<String>,

    /// Suffix/end pattern (end of address)
    /// Example: '777' finds '...777', '9' finds '...9'
    #[arg(short = 'e', long = "end", value_name = "SUFFIX", help = "Suffix at end (e.g., '777' finds '...777')")]
    suffix_pattern: Option<String>,

    /// Search for pattern at end (deprecated: use -e instead)
    #[arg(short = 's', long = "suffix")]
    suffix_mode: bool,

    /// Number of threads to use (default: all CPU cores)
    #[arg(short = 't', long, value_name = "N")]
    threads: Option<usize>,

    /// Case-sensitive pattern matching (default is case-insensitive)
    #[arg(short = 'c', long = "case-sensitive")]
    case_sensitive: bool,

    /// Show detailed progress information
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Show hardware information
    #[arg(long = "info")]
    show_info: bool,

    /// Run benchmark mode (10 second test)
    #[arg(long = "benchmark")]
    benchmark: bool,

    /// Use Metal GPU for Keccak-256 hashing (experimental)
    /// Note: Currently slower than CPU due to secp256k1 bottleneck
    #[arg(long = "gpu")]
    use_gpu: bool,

    /// Use GPU-native acceleration (full EC math on GPU)
    #[arg(long = "gpu-native")]
    use_gpu_native: bool,
}

fn main() {
    let cli = Cli::parse();

    // Handle benchmark mode
    if cli.benchmark {
        run_benchmark(cli.threads);
        return;
    }

    // Handle hardware info display
    if cli.show_info {
        display_hardware_info();
        if cli.pattern.is_empty() && cli.prefix.is_none() && cli.suffix_pattern.is_none() {
            return;
        }
        println!();
    }

    // Parse and validate configuration
    let config = match parse_config(&cli) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Error: {}", err);
            std::process::exit(1);
        }
    };

    // Validate pattern characters
    if let Some(ref p) = config.prefix {
        if let Err(e) = validate_pattern(p) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
    if let Some(ref s) = config.suffix {
        if let Err(e) = validate_pattern(s) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }

    // Determine thread count
    let num_threads = cli.threads.unwrap_or_else(num_cpus::get);

    // Check GPU availability if requested
    if (cli.use_gpu || cli.use_gpu_native) && !is_gpu_available() {
        eprintln!("Error: GPU acceleration requested but Metal is not available on this system");
        std::process::exit(1);
    }

    // Display configuration
    println!("\nSearching for addresses like: {} [{}]",
        config.pattern_description(),
        if config.case_sensitive { "case-sensitive" } else { "case-insensitive" }
    );

    // Show acceleration mode
    if cli.use_gpu_native {
        println!("Acceleration: Metal GPU (native - full EC math on GPU)");
    } else if cli.use_gpu {
        println!("Acceleration: Metal GPU (hybrid CPU/GPU pipeline)");
    } else {
        println!("Acceleration: CPU-only");
    }

    // Show helpful examples if this is the first time
    if config.prefix.is_some() || config.suffix.is_some() {
        println!("\nExamples:");
        println!("  -p ABC     → finds TABC...xxxxx");
        println!("  -p R5      → finds TR5...xxxxx");
        println!("  -e 777     → finds Txxxxx...777");
        println!("  -p AB -e 9 → finds TAB...xxxxx9");
    }

    println!("\nPress Ctrl+C to stop\n");

    // Setup Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");

    // Create channel for found addresses
    let (tx, rx) = mpsc::channel::<FoundAddress>();

    // Create stats tracker
    let attempts = Arc::new(AtomicU64::new(0));
    let start_time = std::time::Instant::now();

    // Handle GPU-native mode (takes precedence)
    if cli.use_gpu_native {
        if config.prefix.is_none() && config.suffix.is_none() {
            eprintln!("Error: GPU-native mode requires -p (prefix) or -e (suffix)");
            std::process::exit(1);
        }
        if let Err(e) = run_gpu_native_search(&config, running.clone(), attempts.clone()) {
            eprintln!("\nGPU-native search failed: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // Start continuous search in background
    if cli.use_gpu {
        // Use GPU-accelerated search
        if let Err(e) = search_continuous_gpu(config.clone(), num_threads, tx, running.clone(), attempts.clone()) {
            eprintln!("GPU initialization failed: {}", e);
            std::process::exit(1);
        }
    } else {
        // Use CPU-only search
        search_continuous(config.clone(), num_threads, tx, running.clone(), attempts.clone());
    }

    // Main loop: print results and update stats
    let mut found_count = 0u64;

    while running.load(Ordering::SeqCst) {
        // Check for new matches (non-blocking)
        while let Ok(found) = rx.try_recv() {
            found_count += 1;
            println!("{} - {}", found.address, found.private_key);
        }

        // Update stats line (in place)
        let scanned = attempts.load(Ordering::Relaxed);
        let elapsed = start_time.elapsed();
        let rate = if elapsed.as_secs() > 0 {
            (scanned as f64 / elapsed.as_secs_f64()) as u64
        } else {
            0
        };

        print!("\r[Stats] Found: {} | Scanned: {} | Speed: {}/s | Running: {}",
            found_count,
            format_number(scanned),
            format_speed(rate),
            format_running_time(elapsed)
        );
        std::io::stdout().flush().unwrap();

        std::thread::sleep(Duration::from_millis(100));
    }

    // Wait a moment for any final messages
    std::thread::sleep(Duration::from_millis(200));

    // Collect any remaining found addresses
    while let Ok(found) = rx.try_recv() {
        found_count += 1;
        println!("\n{} - {}", found.address, found.private_key);
    }

    // Final stats on Ctrl+C
    let final_scanned = attempts.load(Ordering::Relaxed);
    let final_elapsed = start_time.elapsed();
    let final_rate = if final_elapsed.as_secs() > 0 {
        (final_scanned as f64 / final_elapsed.as_secs_f64()) as u64
    } else {
        0
    };

    println!("\n\nFinal Stats:");
    println!("  Total found:   {}", found_count);
    println!("  Total scanned: {}", format_number(final_scanned));
    println!("  Total time:    {}", format_duration(final_elapsed));
    println!("  Avg speed:     {}/s", format_speed(final_rate));

    if found_count > 0 {
        println!("\nWARNING: Keep your private keys secure! Anyone with these keys can access your funds.");
    }
}

/// Parse CLI arguments into a VanityConfig
fn parse_config(cli: &Cli) -> Result<VanityConfig, String> {
    let case_sensitive = cli.case_sensitive;

    // Handle new-style arguments (-p/-e flags)
    if cli.prefix.is_some() || cli.suffix_pattern.is_some() {
        if !cli.pattern.is_empty() {
            return Err("Cannot use positional PATTERN with -p/--prefix or -e/--end flags".to_string());
        }

        // Strip leading 'T' from prefix since all Tron addresses start with 'T'
        let prefix = cli.prefix.as_ref().map(|p| strip_leading_t(p));

        return Ok(VanityConfig::new(
            prefix,
            cli.suffix_pattern.clone(),
            case_sensitive
        ));
    }

    // Handle backward compatibility
    if !cli.pattern.is_empty() {
        if cli.suffix_mode {
            return Ok(VanityConfig::suffix_only(cli.pattern.clone(), case_sensitive));
        } else {
            // Strip leading 'T' from prefix pattern
            let pattern = strip_leading_t(&cli.pattern);
            return Ok(VanityConfig::prefix_only(pattern, case_sensitive));
        }
    }

    Err("No pattern specified. Use PATTERN or -p/-e flags.".to_string())
}

/// Strip leading 'T' from pattern if present
/// Since all Tron addresses start with 'T', we auto-strip it to avoid confusion
fn strip_leading_t(pattern: &str) -> String {
    let upper = pattern.to_uppercase();
    if upper.starts_with('T') && pattern.len() > 1 {
        pattern[1..].to_string()
    } else {
        pattern.to_string()
    }
}

/// Validate that a pattern contains only Base58 characters
fn validate_pattern(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("Pattern cannot be empty".to_string());
    }

    let valid_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for ch in pattern.chars() {
        if !valid_chars.contains(ch) {
            return Err(format!(
                "Pattern contains invalid character '{}'. Use only Base58 characters (no 0, O, I, l)",
                ch
            ));
        }
    }
    Ok(())
}

/// Run benchmark mode
fn run_benchmark(threads: Option<usize>) {
    use std::time::Instant;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};

    let num_threads = threads.unwrap_or_else(num_cpus::get);

    println!("Tron Vanity Generator - Benchmark Mode");
    println!("=======================================");
    println!();

    display_hardware_info();
    println!();

    println!("Running 10-second benchmark with {} threads...", num_threads);
    println!();

    let start = Instant::now();
    let duration = Duration::from_secs(10);
    let keys_generated = Arc::new(AtomicU64::new(0));
    let stop_flag = Arc::new(AtomicBool::new(false));

    // Spawn worker threads
    let mut handles = vec![];
    for _ in 0..num_threads {
        let keys = keys_generated.clone();
        let stop = stop_flag.clone();
        let start_time = start;

        let handle = std::thread::spawn(move || {
            let mut count = 0u64;
            let mut generator = SequentialGenerator::new();

            while !stop.load(Ordering::Relaxed) {
                for _ in 0..10_000 {
                    let (_, public_key) = generator.next();
                    let _ = public_key_to_tron_address(public_key);
                    count += 1;
                }

                if start_time.elapsed() >= duration {
                    break;
                }
            }

            keys.fetch_add(count, Ordering::Relaxed);
        });
        handles.push(handle);
    }

    // Wait for duration
    std::thread::sleep(duration);
    stop_flag.store(true, Ordering::Relaxed);

    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }

    let elapsed = start.elapsed();
    let total_keys = keys_generated.load(Ordering::Relaxed);
    let avg_speed = total_keys as f64 / elapsed.as_secs_f64();

    println!("Benchmark Results:");
    println!("  Keys generated:  {}", format_number(total_keys));
    println!("  Time:            {:.1}s", elapsed.as_secs_f64());
    println!("  Average speed:   {:.2}M keys/sec", avg_speed / 1_000_000.0);
    println!();

    // Show estimated search times
    println!("Estimated search times (case-sensitive):");
    for len in 3..=7 {
        let diff = 58u64.saturating_pow(len);
        let time = diff as f64 / avg_speed;
        println!("  {} chars:  {}", len, format_duration(Duration::from_secs_f64(time)));
    }
}

/// Format running time in a compact way
fn format_running_time(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

/// Run GPU-native search (full EC math + Keccak on GPU)
fn run_gpu_native_search(
    config: &VanityConfig,
    running: Arc<AtomicBool>,
    attempts: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tron_vanity_generator::gpu::native_search::{
        GpuNativeSearcher, GpuSuffixSearcher, generate_gpu_seeds,
        prefix_to_target_range, suffix_to_target, recover_private_key
    };

    let context = tron_vanity_generator::gpu::initialize()?;

    // GPU configuration - optimized for 100M+ keys/sec
    // Note: GLV endomorphism currently disabled in shaders due to performance issues
    let num_threads = 131072;  // GPU threads (2x baseline, optimal for this GPU)
    let steps_per_thread = 2048;  // Steps per kernel launch

    // Determine if we're doing prefix or suffix search
    let is_suffix_mode = config.suffix.is_some();
    println!("Kernel: {}", if is_suffix_mode { "tron_suffix_search (SHA256)" } else { "tron_vanity_search (Range Check)" });

    if is_suffix_mode {
        // SUFFIX SEARCH
        let suffix = config.suffix.as_ref().ok_or("Suffix required for suffix mode")?;
        let (target_modulus, target_remainder) = suffix_to_target(suffix);

        let searcher = GpuSuffixSearcher::new(context, num_threads, steps_per_thread)?;

        println!("GPU-Native Suffix Mode: {} threads × {} steps = {} keys/batch",
            num_threads, steps_per_thread, (num_threads as u64) * (steps_per_thread as u64));
        println!("Searching for suffix: '{}' (mod={}, rem={})", suffix, target_modulus, target_remainder);

        let start_time = std::time::Instant::now();
        let mut found_count = 0u64;
        let mut batch_count = 0u64;

        while running.load(Ordering::SeqCst) {
            let (points, privkeys, base_key) = generate_gpu_seeds(num_threads, steps_per_thread as u64)?;

            // Calculate prefix parameters if both prefix and suffix specified
            let (prefix_min, prefix_max, prefix_check_len) = if let Some(ref prefix) = config.prefix {
                let (min, max) = prefix_to_target_range(prefix);
                (Some(min), Some(max), prefix.len().min(20) as u32)
            } else {
                (None, None, 0)
            };

            if let Some((thread_id, offset)) = searcher.search_iteration(
                &points, &privkeys, target_modulus, target_remainder,
                prefix_min.as_ref(), prefix_max.as_ref(), prefix_check_len
            )? {
                // Handle endomorphism matches
                let is_endomorphism = offset > 100000;
                let actual_offset = if is_endomorphism { offset - 100000 } else { offset };
                let mut found_key = recover_private_key(&base_key, thread_id, actual_offset, steps_per_thread as u64)?;

                // If endomorphism match, multiply private key by lambda mod n
                if is_endomorphism {
                    found_key = multiply_by_lambda(found_key)?;
                }

                let secp = secp256k1::Secp256k1::new();
                let pub_key = secp256k1::PublicKey::from_secret_key(&secp, &found_key);
                let address = public_key_to_tron_address(&pub_key);
                let private_hex = hex::encode(found_key.secret_bytes());

                found_count += 1;
                println!("\n{} - {}", address, private_hex);
            }

            batch_count += 1;
            let total_keys = batch_count * (num_threads as u64) * (steps_per_thread as u64);
            attempts.store(total_keys, Ordering::Relaxed);

            let elapsed = start_time.elapsed();
            let rate = total_keys as f64 / elapsed.as_secs_f64();
            print!("\r[GPU-Native Suffix] Found: {} | Scanned: {} | Speed: {:.2}M/s",
                found_count, format_number(total_keys), rate / 1_000_000.0);
            std::io::stdout().flush().unwrap();
        }
    } else {
        // PREFIX SEARCH (existing code)
        let searcher = GpuNativeSearcher::new(context, num_threads, steps_per_thread)?;

        let prefix = config.prefix.as_ref().ok_or("GPU-native requires prefix or suffix search")?;
        let (target_min, target_max) = prefix_to_target_range(prefix);
        let check_len = prefix.len().min(20) as u32;

        println!("GPU-Native Mode: {} threads × {} steps = {} keys/batch",
            num_threads, steps_per_thread, (num_threads as u64) * (steps_per_thread as u64));

        let start_time = std::time::Instant::now();
        let mut found_count = 0u64;
        let mut batch_count = 0u64;

        while running.load(Ordering::SeqCst) {
            let (points, privkeys, base_key) = generate_gpu_seeds(num_threads, steps_per_thread as u64)?;

            if let Some((thread_id, offset)) = searcher.search_iteration(
                &points, &privkeys, &target_min, &target_max, check_len
            )? {
                // Handle endomorphism matches
                let is_endomorphism = offset > 100000;
                let actual_offset = if is_endomorphism { offset - 100000 } else { offset };
                let mut found_key = recover_private_key(&base_key, thread_id, actual_offset, steps_per_thread as u64)?;

                // If endomorphism match, multiply private key by lambda mod n
                if is_endomorphism {
                    found_key = multiply_by_lambda(found_key)?;
                }

                let secp = secp256k1::Secp256k1::new();
                let pub_key = secp256k1::PublicKey::from_secret_key(&secp, &found_key);
                let address = public_key_to_tron_address(&pub_key);
                let private_hex = hex::encode(found_key.secret_bytes());

                found_count += 1;
                println!("\n{} - {}", address, private_hex);
            }

            batch_count += 1;
            let total_keys = batch_count * (num_threads as u64) * (steps_per_thread as u64);
            attempts.store(total_keys, Ordering::Relaxed);

            let elapsed = start_time.elapsed();
            let rate = total_keys as f64 / elapsed.as_secs_f64();
            print!("\r[GPU-Native] Found: {} | Scanned: {} | Speed: {:.2}M/s",
                found_count, format_number(total_keys), rate / 1_000_000.0);
            std::io::stdout().flush().unwrap();
        }
    }

    Ok(())
}

/// Multiply a private key by lambda (GLV endomorphism scalar)
/// Lambda is the eigenvalue for secp256k1 endomorphism: ψ(x,y) = (β·x, y) = λ·P
fn multiply_by_lambda(key: secp256k1::SecretKey) -> Result<secp256k1::SecretKey, Box<dyn std::error::Error>> {
    use num_bigint::BigUint;
    use secp256k1::SecretKey;

    // Lambda constant for secp256k1 GLV endomorphism
    // λ = 0x5363ad4cc05c30e0a5261c029812645a122e22ea20816678df02967c1b23bd72
    let lambda_bytes: [u8; 32] = [
        0x53, 0x63, 0xad, 0x4c, 0xc0, 0x5c, 0x30, 0xe0,
        0xa5, 0x26, 0x1c, 0x02, 0x98, 0x12, 0x64, 0x5a,
        0x12, 0x2e, 0x22, 0xea, 0x20, 0x81, 0x66, 0x78,
        0xdf, 0x02, 0x96, 0x7c, 0x1b, 0x23, 0xbd, 0x72
    ];

    // Secp256k1 curve order n
    // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    let n_bytes: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
    ];

    // Convert to BigUint
    let key_bytes = key.secret_bytes();
    let key_big = BigUint::from_bytes_be(&key_bytes);
    let lambda_big = BigUint::from_bytes_be(&lambda_bytes);
    let n_big = BigUint::from_bytes_be(&n_bytes);

    // Multiply: result = (key * lambda) mod n
    let result = (key_big * lambda_big) % n_big;

    // Convert back to 32-byte array
    let result_bytes = result.to_bytes_be();
    let mut key_array = [0u8; 32];
    let start = 32 - result_bytes.len();
    key_array[start..].copy_from_slice(&result_bytes);

    // Create SecretKey
    SecretKey::from_slice(&key_array)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

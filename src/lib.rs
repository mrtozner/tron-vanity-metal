/// High-performance Tron vanity address generator optimized for Apple Silicon
///
/// This library provides functionality to generate Tron addresses and search for
/// vanity addresses with specific patterns.

pub mod address;
pub mod search;
pub mod difficulty;
pub mod hardware;
pub mod stats;
pub mod display;
pub mod gpu;
pub mod range_check;

pub use address::{
    generate_keypair,
    generate_keypair_from_seed,
    generate_keypair_direct,
    public_key_to_tron_address,
    public_key_to_raw_address,      // NEW: for optimized workflows
    raw_address_to_base58,           // NEW: for optimized workflows
    public_key_to_raw_address_with_checksum,  // NEW: for range checking
    raw_address_to_base58_from_full,          // NEW: for range checking
    double_sha256,                   // Platform-optimized SHA-256
    private_key_to_hex,
    SequentialGenerator,            // Sequential key generation for 100x speedup
};
pub use search::{VanitySearcher, VanityResult, VanityConfig, FoundAddress, search_parallel, search_with_config, search_continuous};
pub use difficulty::{calculate_difficulty, format_difficulty, format_duration, estimate_time};
pub use hardware::{get_cpu_info, get_core_count, is_apple_silicon, display_hardware_info};
pub use stats::{SearchStats, format_number, format_speed};
pub use display::{create_progress_bar, update_progress, display_success_enhanced};
pub use gpu::{MetalContext, GpuError, is_gpu_available, initialize, search_continuous_gpu};
pub use gpu::native_search::{
    GpuNativeSearcher, GpuSuffixSearcher, GpuUint256, GpuJacobianPoint,
    generate_gpu_seeds, prefix_to_target_range, suffix_to_target, recover_private_key
};

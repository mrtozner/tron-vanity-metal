//! GPU-Native Vanity Search
//! Runs the full EC math + Keccak on GPU for maximum speed

use crate::gpu::{GpuError, MetalContext};
use crate::range_check::PrefixRange;
use secp256k1::{PublicKey, SecretKey, Secp256k1, Scalar};
use std::sync::Arc;

// ==========================================
// GPU-Compatible Structs
// ==========================================

/// Must match uint256_t in Metal (8 x u32, little-endian)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GpuUint256 {
    pub d: [u32; 8],
}

/// Must match JacobianPoint in Metal
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GpuJacobianPoint {
    pub x: GpuUint256,
    pub y: GpuUint256,
    pub z: GpuUint256,
}

impl From<[u8; 32]> for GpuUint256 {
    fn from(bytes: [u8; 32]) -> Self {
        let mut d = [0u32; 8];
        // Convert big-endian bytes to little-endian limbs
        for i in 0..8 {
            let start = (7 - i) * 4;
            d[i] = u32::from_be_bytes([
                bytes[start], bytes[start+1], bytes[start+2], bytes[start+3]
            ]);
        }
        Self { d }
    }
}

impl GpuUint256 {
    pub fn one() -> Self {
        let mut d = [0u32; 8];
        d[0] = 1;
        Self { d }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..8 {
            let limb = self.d[7 - i];
            let start = i * 4;
            bytes[start..start+4].copy_from_slice(&limb.to_be_bytes());
        }
        bytes
    }
}

// ==========================================
// Seed Generation
// ==========================================

/// Generate GPU seeds - starting points spread across search space
pub fn generate_gpu_seeds(
    num_threads: usize,
    steps_per_thread: u64,
) -> Result<(Vec<GpuJacobianPoint>, Vec<GpuUint256>, SecretKey), GpuError> {
    let secp = Secp256k1::new();

    // Generate random base private key
    let base_key = SecretKey::new(&mut rand::thread_rng());

    let mut points = Vec::with_capacity(num_threads);
    let mut privkeys = Vec::with_capacity(num_threads);

    // Offset between threads
    let offset_bytes = steps_per_thread.to_be_bytes();
    let mut offset_32 = [0u8; 32];
    offset_32[24..32].copy_from_slice(&offset_bytes);
    let offset_scalar = Scalar::from_be_bytes(offset_32)
        .map_err(|_| GpuError::InitializationFailed("Invalid scalar".to_string()))?;

    let mut current_key = base_key;

    for _ in 0..num_threads {
        // Get public key
        let pub_key = PublicKey::from_secret_key(&secp, &current_key);
        let serialized = pub_key.serialize_uncompressed();

        // Extract X and Y (skip 0x04 prefix)
        let x_bytes: [u8; 32] = serialized[1..33].try_into().unwrap();
        let y_bytes: [u8; 32] = serialized[33..65].try_into().unwrap();

        // Create Jacobian point (Z = 1)
        let gpu_point = GpuJacobianPoint {
            x: GpuUint256::from(x_bytes),
            y: GpuUint256::from(y_bytes),
            z: GpuUint256::one(),
        };

        // Store private key for result recovery
        let priv_bytes: [u8; 32] = current_key.secret_bytes();

        points.push(gpu_point);
        privkeys.push(GpuUint256::from(priv_bytes));

        // Advance to next thread's starting position
        current_key = current_key.add_tweak(&offset_scalar)
            .map_err(|_| GpuError::InitializationFailed("Key overflow".to_string()))?;
    }

    Ok((points, privkeys, base_key))
}

/// Convert prefix pattern to target range bytes
pub fn prefix_to_target_range(prefix: &str) -> ([u8; 20], [u8; 20]) {
    let range = PrefixRange::from_prefix(prefix);

    // Extract just the address portion (bytes 1-21 of the 25-byte address)
    let mut min = [0u8; 20];
    let mut max = [0xffu8; 20];

    min.copy_from_slice(&range.min[1..21]);
    max.copy_from_slice(&range.max[1..21]);

    (min, max)
}

/// Convert suffix pattern to modulus and remainder for GPU matching
/// Example: "777" → modulus=58^3=195112, remainder=decode("777")=41664
pub fn suffix_to_target(suffix: &str) -> (u64, u64) {
    const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let n = suffix.len();
    let modulus: u64 = 58u64.pow(n as u32);

    let mut remainder: u64 = 0;
    for ch in suffix.chars() {
        let idx = ALPHABET.find(ch).unwrap_or(0) as u64;
        remainder = remainder * 58 + idx;
    }

    (modulus, remainder)
}

// ==========================================
// GPU Search Execution
// ==========================================

pub struct GpuNativeSearcher {
    context: Arc<MetalContext>,
    pipeline: metal::ComputePipelineState,
    num_threads: usize,
    steps_per_thread: u32,
}

impl GpuNativeSearcher {
    pub fn new(context: Arc<MetalContext>, num_threads: usize, steps_per_thread: u32) -> Result<Self, GpuError> {
        // Load and compile the search_native.metal shader
        let shader_source = include_str!("search_native.metal");

        let library = context.device()
            .new_library_with_source(shader_source, &metal::CompileOptions::new())
            .map_err(|e| GpuError::ShaderCompilationFailed(e.to_string()))?;

        let function = library.get_function("tron_vanity_search", None)
            .map_err(|e| GpuError::ShaderCompilationFailed(e.to_string()))?;

        let pipeline = context.device()
            .new_compute_pipeline_state_with_function(&function)
            .map_err(|e| GpuError::PipelineCreationFailed(e.to_string()))?;

        Ok(Self {
            context,
            pipeline,
            num_threads,
            steps_per_thread,
        })
    }

    /// Run a single search iteration
    /// Returns (found, thread_id, offset) if match found
    pub fn search_iteration(
        &self,
        points: &[GpuJacobianPoint],
        privkeys: &[GpuUint256],
        target_min: &[u8; 20],
        target_max: &[u8; 20],
        check_len: u32,
    ) -> Result<Option<(u32, u32)>, GpuError> {
        let device = self.context.device();

        // Create buffers
        let points_buffer = device.new_buffer_with_data(
            points.as_ptr() as *const _,
            (points.len() * std::mem::size_of::<GpuJacobianPoint>()) as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let privkeys_buffer = device.new_buffer_with_data(
            privkeys.as_ptr() as *const _,
            (privkeys.len() * std::mem::size_of::<GpuUint256>()) as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let target_min_buffer = device.new_buffer_with_data(
            target_min.as_ptr() as *const _,
            20,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let target_max_buffer = device.new_buffer_with_data(
            target_max.as_ptr() as *const _,
            20,
            metal::MTLResourceOptions::StorageModeShared,
        );

        // Result buffers
        let found_flag: u32 = 0;
        let found_buffer = device.new_buffer_with_data(
            &found_flag as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let result_thread: u32 = 0;
        let result_thread_buffer = device.new_buffer_with_data(
            &result_thread as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let result_offset: u32 = 0;
        let result_offset_buffer = device.new_buffer_with_data(
            &result_offset as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let steps_buffer = device.new_buffer_with_data(
            &self.steps_per_thread as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let check_len_buffer = device.new_buffer_with_data(
            &check_len as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        // Create command buffer
        let command_buffer = self.context.command_queue().new_command_buffer();
        let encoder = command_buffer.new_compute_command_encoder();

        encoder.set_compute_pipeline_state(&self.pipeline);
        encoder.set_buffer(0, Some(&points_buffer), 0);
        encoder.set_buffer(1, Some(&privkeys_buffer), 0);
        encoder.set_buffer(2, Some(&target_min_buffer), 0);
        encoder.set_buffer(3, Some(&target_max_buffer), 0);
        encoder.set_buffer(4, Some(&found_buffer), 0);
        encoder.set_buffer(5, Some(&result_thread_buffer), 0);
        encoder.set_buffer(6, Some(&result_offset_buffer), 0);
        encoder.set_buffer(7, Some(&steps_buffer), 0);
        encoder.set_buffer(8, Some(&check_len_buffer), 0);

        // Dispatch
        let threads_per_group = 256u64;
        let grid_size = metal::MTLSize::new(self.num_threads as u64, 1, 1);
        let group_size = metal::MTLSize::new(threads_per_group.min(self.num_threads as u64), 1, 1);

        encoder.dispatch_threads(grid_size, group_size);
        encoder.end_encoding();

        command_buffer.commit();
        command_buffer.wait_until_completed();

        // Read results
        let found_ptr = found_buffer.contents() as *const u32;
        let found = unsafe { *found_ptr };

        if found > 0 {
            let thread_ptr = result_thread_buffer.contents() as *const u32;
            let offset_ptr = result_offset_buffer.contents() as *const u32;
            let thread_id = unsafe { *thread_ptr };
            let offset = unsafe { *offset_ptr };
            Ok(Some((thread_id, offset)))
        } else {
            Ok(None)
        }
    }
}

/// Recover private key from search result
pub fn recover_private_key(
    base_key: &SecretKey,
    thread_id: u32,
    offset: u32,
    steps_per_thread: u64,
) -> Result<SecretKey, GpuError> {
    // Total offset = thread_id * steps_per_thread + offset
    let total_offset = (thread_id as u64) * steps_per_thread + (offset as u64);

    let mut offset_bytes = [0u8; 32];
    offset_bytes[24..32].copy_from_slice(&total_offset.to_be_bytes());

    let offset_scalar = Scalar::from_be_bytes(offset_bytes)
        .map_err(|_| GpuError::InitializationFailed("Invalid offset".to_string()))?;

    base_key.add_tweak(&offset_scalar)
        .map_err(|_| GpuError::InitializationFailed("Key recovery failed".to_string()))
}

// ==========================================
// GPU Suffix Search
// ==========================================

pub struct GpuSuffixSearcher {
    context: Arc<MetalContext>,
    pipeline: metal::ComputePipelineState,
    num_threads: usize,
    steps_per_thread: u32,
}

impl GpuSuffixSearcher {
    pub fn new(context: Arc<MetalContext>, num_threads: usize, steps_per_thread: u32) -> Result<Self, GpuError> {
        let shader_source = include_str!("search_suffix.metal");

        let library = context.device()
            .new_library_with_source(shader_source, &metal::CompileOptions::new())
            .map_err(|e| GpuError::ShaderCompilationFailed(e.to_string()))?;

        let function = library.get_function("tron_suffix_search", None)
            .map_err(|e| GpuError::ShaderCompilationFailed(e.to_string()))?;

        let pipeline = context.device()
            .new_compute_pipeline_state_with_function(&function)
            .map_err(|e| GpuError::PipelineCreationFailed(e.to_string()))?;

        Ok(Self {
            context,
            pipeline,
            num_threads,
            steps_per_thread,
        })
    }

    /// Run a single suffix search iteration
    /// Returns (thread_id, offset) if match found
    pub fn search_iteration(
        &self,
        points: &[GpuJacobianPoint],
        privkeys: &[GpuUint256],
        target_modulus: u64,
        target_remainder: u64,
        prefix_min: Option<&[u8; 20]>,
        prefix_max: Option<&[u8; 20]>,
        prefix_check_len: u32,
    ) -> Result<Option<(u32, u32)>, GpuError> {
        let device = self.context.device();

        // Create buffers
        let points_buffer = device.new_buffer_with_data(
            points.as_ptr() as *const _,
            (points.len() * std::mem::size_of::<GpuJacobianPoint>()) as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let privkeys_buffer = device.new_buffer_with_data(
            privkeys.as_ptr() as *const _,
            (privkeys.len() * std::mem::size_of::<GpuUint256>()) as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let modulus_buffer = device.new_buffer_with_data(
            &target_modulus as *const _ as *const _,
            8,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let remainder_buffer = device.new_buffer_with_data(
            &target_remainder as *const _ as *const _,
            8,
            metal::MTLResourceOptions::StorageModeShared,
        );

        // Result buffers
        let found_flag: u32 = 0;
        let found_buffer = device.new_buffer_with_data(
            &found_flag as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let result_thread: u32 = 0;
        let result_thread_buffer = device.new_buffer_with_data(
            &result_thread as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let result_offset: u32 = 0;
        let result_offset_buffer = device.new_buffer_with_data(
            &result_offset as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let steps_buffer = device.new_buffer_with_data(
            &self.steps_per_thread as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        // Prefix buffers (use dummy data if no prefix)
        let dummy_prefix = [0u8; 20];
        let prefix_min_ref = prefix_min.unwrap_or(&dummy_prefix);
        let prefix_max_ref = prefix_max.unwrap_or(&dummy_prefix);

        let prefix_min_buffer = device.new_buffer_with_data(
            prefix_min_ref.as_ptr() as *const _,
            20,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let prefix_max_buffer = device.new_buffer_with_data(
            prefix_max_ref.as_ptr() as *const _,
            20,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let prefix_len_buffer = device.new_buffer_with_data(
            &prefix_check_len as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        // Create command buffer
        let command_buffer = self.context.command_queue().new_command_buffer();
        let encoder = command_buffer.new_compute_command_encoder();

        encoder.set_compute_pipeline_state(&self.pipeline);
        encoder.set_buffer(0, Some(&points_buffer), 0);
        encoder.set_buffer(1, Some(&privkeys_buffer), 0);
        encoder.set_buffer(2, Some(&modulus_buffer), 0);
        encoder.set_buffer(3, Some(&remainder_buffer), 0);
        encoder.set_buffer(4, Some(&found_buffer), 0);
        encoder.set_buffer(5, Some(&result_thread_buffer), 0);
        encoder.set_buffer(6, Some(&result_offset_buffer), 0);
        encoder.set_buffer(7, Some(&steps_buffer), 0);
        encoder.set_buffer(8, Some(&prefix_min_buffer), 0);
        encoder.set_buffer(9, Some(&prefix_max_buffer), 0);
        encoder.set_buffer(10, Some(&prefix_len_buffer), 0);

        // Dispatch
        let threads_per_group = 256u64;
        let grid_size = metal::MTLSize::new(self.num_threads as u64, 1, 1);
        let group_size = metal::MTLSize::new(threads_per_group.min(self.num_threads as u64), 1, 1);

        encoder.dispatch_threads(grid_size, group_size);
        encoder.end_encoding();

        command_buffer.commit();
        command_buffer.wait_until_completed();

        // Read results
        let found_ptr = found_buffer.contents() as *const u32;
        let found = unsafe { *found_ptr };

        if found > 0 {
            let thread_ptr = result_thread_buffer.contents() as *const u32;
            let offset_ptr = result_offset_buffer.contents() as *const u32;
            let thread_id = unsafe { *thread_ptr };
            let offset = unsafe { *offset_ptr };
            Ok(Some((thread_id, offset)))
        } else {
            Ok(None)
        }
    }
}

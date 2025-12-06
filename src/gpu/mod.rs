/// GPU acceleration module using Metal for macOS
///
/// This module provides GPU-accelerated Keccak-256 hashing for TRON address generation
/// on Apple Silicon and Intel Macs with Metal support.

pub mod pipeline;
pub mod search;
pub mod native_search;

use metal::{Device, CommandQueue};
use std::sync::Arc;

/// Metal GPU context holding device and command queue
pub struct MetalContext {
    pub device: Device,
    pub command_queue: CommandQueue,
}

/// Error types for GPU operations
#[derive(Debug)]
pub enum GpuError {
    MetalNotAvailable,
    DeviceCreationFailed,
    CommandQueueCreationFailed,
    ShaderCompilationFailed(String),
    BufferCreationFailed,
    ComputeEncodingFailed,
    InitializationFailed(String),
    PipelineCreationFailed(String),
}

impl std::fmt::Display for GpuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuError::MetalNotAvailable => write!(f, "Metal is not available on this system"),
            GpuError::DeviceCreationFailed => write!(f, "Failed to create Metal device"),
            GpuError::CommandQueueCreationFailed => write!(f, "Failed to create command queue"),
            GpuError::ShaderCompilationFailed(msg) => write!(f, "Shader compilation failed: {}", msg),
            GpuError::BufferCreationFailed => write!(f, "Failed to create Metal buffer"),
            GpuError::ComputeEncodingFailed => write!(f, "Failed to encode compute command"),
            GpuError::InitializationFailed(msg) => write!(f, "Initialization failed: {}", msg),
            GpuError::PipelineCreationFailed(msg) => write!(f, "Pipeline creation failed: {}", msg),
        }
    }
}

impl std::error::Error for GpuError {}

impl MetalContext {
    /// Create a new Metal context with default device
    pub fn new() -> Result<Self, GpuError> {
        // Get default Metal device
        let device = Device::system_default()
            .ok_or(GpuError::MetalNotAvailable)?;

        // Create command queue
        let command_queue = device.new_command_queue();

        Ok(MetalContext {
            device,
            command_queue,
        })
    }

    /// Check if Metal is available on this system
    pub fn is_available() -> bool {
        Device::system_default().is_some()
    }

    /// Get device name for logging
    pub fn device_name(&self) -> String {
        self.device.name().to_string()
    }

    /// Get device reference
    pub fn device(&self) -> &metal::Device {
        &self.device
    }

    /// Get command queue reference
    pub fn command_queue(&self) -> &metal::CommandQueue {
        &self.command_queue
    }
}

/// Check if GPU acceleration is available
pub fn is_gpu_available() -> bool {
    MetalContext::is_available()
}

/// Initialize GPU context (convenience function)
pub fn initialize() -> Result<Arc<MetalContext>, GpuError> {
    MetalContext::new().map(Arc::new)
}

// Re-export GPU search function
pub use search::search_continuous_gpu;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metal_availability() {
        // This test will pass on macOS with Metal, fail on other systems
        let available = is_gpu_available();
        println!("Metal available: {}", available);

        if available {
            let context = MetalContext::new();
            assert!(context.is_ok());

            if let Ok(ctx) = context {
                println!("Metal device: {}", ctx.device_name());
            }
        }
    }
}

use sysinfo::System;

/// Get CPU model name
pub fn get_cpu_info() -> String {
    let mut sys = System::new_all();
    sys.refresh_all();

    if let Some(cpu) = sys.cpus().first() {
        cpu.brand().to_string()
    } else {
        "Unknown CPU".to_string()
    }
}

/// Get core count (returns physical cores, logical threads)
pub fn get_core_count() -> (usize, usize) {
    let physical = num_cpus::get_physical();
    let logical = num_cpus::get();
    (physical, logical)
}

/// Check if running on Apple Silicon
pub fn is_apple_silicon() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

/// Display hardware information
pub fn display_hardware_info() {
    println!("Hardware:");
    println!("  CPU:      {}", get_cpu_info());

    let (physical, logical) = get_core_count();
    if is_apple_silicon() {
        println!("  Cores:    {} ({} threads)", physical, logical);
        println!("  Arch:     Apple Silicon (ARM64)");
    } else {
        println!("  Cores:    {} physical ({} logical)", physical, logical);
    }

    let mut sys = System::new_all();
    sys.refresh_all();
    let total_mem_gb = sys.total_memory() as f64 / 1_073_741_824.0;
    println!("  Memory:   {:.1}GB", total_mem_gb);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cpu_info() {
        let cpu = get_cpu_info();
        assert!(!cpu.is_empty());
    }

    #[test]
    fn test_get_core_count() {
        let (physical, logical) = get_core_count();
        assert!(physical > 0);
        assert!(logical >= physical);
    }

    #[test]
    fn test_is_apple_silicon() {
        // Just ensure it doesn't panic
        let _ = is_apple_silicon();
    }
}

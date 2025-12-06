#!/bin/bash
# Build script for Tron Vanity Generator with Apple Silicon optimizations

set -e

echo "Building Tron Vanity Generator for Apple Silicon..."
echo "=================================================="
echo ""

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "Error: Rust is not installed. Please install from https://rustup.rs/"
    exit 1
fi

# Check Rust version
RUST_VERSION=$(rustc --version | cut -d' ' -f2)
echo "Rust version: $RUST_VERSION"
echo ""

# Build with Apple Silicon optimizations
echo "Building with native CPU optimizations..."
RUSTFLAGS="-C target-cpu=native" cargo build --release

echo ""
echo "Build complete!"
echo "==============="
echo ""
echo "Binary location: target/release/tron-vanity-generator"
echo ""
echo "Run tests with:"
echo "  cargo test --release"
echo ""
echo "Try it out with:"
echo "  ./target/release/tron-vanity-generator A"
echo ""

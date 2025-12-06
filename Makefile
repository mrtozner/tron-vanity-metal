.PHONY: build test clean run help bench install

# Default target
all: build

# Build with Apple Silicon optimizations
build:
	@echo "Building for Apple Silicon..."
	RUSTFLAGS="-C target-cpu=native" cargo build --release

# Run tests
test:
	@echo "Running tests..."
	cargo test --release

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean

# Run with example pattern
run:
	@echo "Running with example pattern 'ABC'..."
	./target/release/tron-vanity-generator -v ABC

# Run benchmarks
bench:
	@echo "Running simple benchmark..."
	@echo "Searching for single character 'A'..."
	@time ./target/release/tron-vanity-generator A

# Install to system (optional)
install: build
	@echo "Installing to /usr/local/bin/..."
	@sudo cp target/release/tron-vanity-generator /usr/local/bin/
	@echo "Installed! Run with: tron-vanity-generator"

# Show help
help:
	@echo "Tron Vanity Generator - Makefile Commands"
	@echo "=========================================="
	@echo ""
	@echo "  make build    - Build the project with optimizations"
	@echo "  make test     - Run all tests"
	@echo "  make clean    - Clean build artifacts"
	@echo "  make run      - Run with example pattern"
	@echo "  make bench    - Run a simple benchmark"
	@echo "  make install  - Install to /usr/local/bin (requires sudo)"
	@echo "  make help     - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  ./target/release/tron-vanity-generator HELLO"
	@echo "  ./target/release/tron-vanity-generator -i -v LUCKY"
	@echo "  ./target/release/tron-vanity-generator -s 777"
	@echo ""

# tron-vanity-metal

**A Metal GPU-accelerated TRON vanity address generator for Apple Silicon.**

Generate custom TRON addresses with specific prefixes or suffixes at blazing speeds using Apple Silicon's native Metal GPU acceleration.

## Performance

| Mode | Speed | Hardware |
|------|-------|----------|
| **Metal GPU (prefix)** | **209 M/s** | Apple M4 Pro |
| **Metal GPU (suffix)** | **158 M/s** | Apple M4 Pro |
| CPU multi-threaded | ~2 M/s | 14-core M4 Pro |

**100x faster than CPU-only generators** on Apple Silicon!

### Difficulty Estimates (at 209 M/s)

| Pattern Length | Approximate Time |
|----------------|-----------------|
| 1-2 characters | Instant |
| 3 characters | < 1 second |
| 4 characters | ~10 seconds |
| 5 characters | ~10 minutes |
| 6 characters | ~6 hours |
| 7 characters | ~2 weeks |

## Features

- **Metal GPU Acceleration** - Native Apple Silicon GPU compute for maximum performance
- **Prefix Search** - Find addresses starting with custom patterns (e.g., `TR5g...`)
- **Suffix Search** - Find addresses ending with patterns (e.g., `...999`)
- **Combined Search** - Match both prefix AND suffix simultaneously
- **Case-Insensitive** - Optional case-insensitive matching
- **Real-time Progress** - Live speed and match counter
- **Secure** - All keys generated locally, never transmitted

## Installation

### Prerequisites

- macOS 12.0+ (Monterey or later)
- Apple Silicon Mac (M1/M2/M3/M4) or Intel Mac with AMD GPU
- Rust 1.70+

### Build from Source

```bash
git clone https://github.com/mrtozner/tron-vanity-metal.git
cd tron-vanity-metal
cargo build --release
```

The binary will be at `./target/release/tron-vanity-generator`.

## Usage

### GPU-Accelerated Search (Recommended)

```bash
# Find address starting with "R5g"
./target/release/tron-vanity-generator -p R5g --gpu-native

# Find address ending with "999"
./target/release/tron-vanity-generator -e 999 --gpu-native

# Find address starting with "R5" AND ending with "9"
./target/release/tron-vanity-generator -p R5 -e 9 --gpu-native
```

### CPU-Only Search (Slower, for testing)

```bash
./target/release/tron-vanity-generator -p R5g
```

### Command Line Options

```
Options:
  -p, --prefix <PREFIX>    Search for addresses starting with this pattern
  -e, --end <SUFFIX>       Search for addresses ending with this pattern
  -c, --case-sensitive     Enable case-sensitive matching
      --gpu-native         Use Metal GPU acceleration (recommended)
      --benchmark          Run performance benchmark
      --info               Show hardware information
  -h, --help               Print help
```

### Output Format

```
TR5gxWvpHzh8KqZ3rdsgePWoCn44WfBvz9 - f834299d16ce4bcd4a48a8cdb76564a99c8ab20069a407a19f2468eab38f78fb
```

Format: `<TRON_ADDRESS> - <PRIVATE_KEY_HEX>`

**IMPORTANT:** Save the private key immediately! It's only displayed once.

## Technical Details

### Algorithm

1. Generate random 256-bit private key (secp256k1)
2. Compute public key point on the elliptic curve
3. Apply Keccak-256 hash to uncompressed public key
4. Take last 20 bytes, prepend `0x41` (TRON mainnet)
5. Base58Check encode to get TRON address
6. Check if address matches pattern
7. Repeat using GPU batch processing (268M keys per batch)

### GPU Optimizations

- **Montgomery Batch Inversion** (window=32): Reduces modular inversions by 32x
- **Jacobian Coordinates**: Avoids expensive inversions during point addition
- **Optimized Keccak-256**: Unrolled permutation for Metal shaders
- **131K GPU Threads**: Parallel processing with 2048 steps each
- **GLV Endomorphism**: (Prepared) Exploits secp256k1 curve property for additional speedup

### Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Rust CLI   │────▶│ Metal Shader │────▶│  GPU Cores  │
│  (main.rs)  │◀────│ (*.metal)    │◀────│  (M4 Pro)   │
└─────────────┘     └──────────────┘     └─────────────┘
      │                                         │
      │         ┌──────────────────┐           │
      └────────▶│  secp256k1 EC    │◀──────────┘
                │  Point Addition  │
                │  Batch Inversion │
                │  Keccak-256 Hash │
                └──────────────────┘
```

## Security

- Private keys are generated using cryptographically secure random number generator
- All computation happens locally on your machine
- No network connections or telemetry
- Keys are displayed once and not stored

**WARNING:**
- Never share your private key
- Test the generated address with a small amount first
- Consider using a hardware wallet for large amounts

## Comparison

| Tool | GPU Support | Speed | Platform |
|------|-------------|-------|----------|
| **tron-vanity-metal** | Metal (native) | **209 M/s** | macOS |
| tron-profanity | CUDA/OpenCL | ~2 GH/s | Linux/Windows |
| vanity-generator (Go) | CPU only | 200 K/s | Cross-platform |
| VanityTron.org | Browser | Very slow | Web |

*Note: This is the only Metal-native implementation, optimized specifically for Apple Silicon.*

## Contributing

Contributions welcome! Areas of interest:

- GLV endomorphism optimization (code ready but disabled due to register pressure)
- Multi-GPU support
- Further Metal shader optimizations
- Other cryptocurrency support (ETH, BTC, SOL)

## License

MIT License - see [LICENSE](LICENSE)

## Changelog

For a detailed list of changes, see the [CHANGELOG.md](CHANGELOG.md) file.

## Acknowledgments

- secp256k1 curve implementation techniques from libsecp256k1
- Montgomery batch inversion algorithm
- Apple Metal Compute documentation

---

**Made with Metal for Apple Silicon**

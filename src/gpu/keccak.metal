#include <metal_stdlib>
using namespace metal;

// Keccak-256 constants
constant ulong keccak_round_constants[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL,
    0x8000000080008000UL, 0x000000000000808bUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008aUL,
    0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL,
    0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800aUL, 0x800000008000000aUL, 0x8000000080008081UL,
    0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

constant int keccak_rotc[24] = {
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

constant int keccak_piln[24] = {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

// Rotate left operation for 64-bit values
inline ulong rotl64(ulong x, int n) {
    return (x << n) | (x >> (64 - n));
}

// Keccak-f[1600] permutation
void keccak_f1600(thread ulong state[25]) {
    ulong bc[5];
    ulong t;

    for (int round = 0; round < 24; round++) {
        // Theta
        for (int i = 0; i < 5; i++) {
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }

        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) {
                state[j + i] ^= t;
            }
        }

        // Rho and Pi
        t = state[1];
        for (int i = 0; i < 24; i++) {
            int j = keccak_piln[i];
            bc[0] = state[j];
            state[j] = rotl64(t, keccak_rotc[i]);
            t = bc[0];
        }

        // Chi
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) {
                bc[i] = state[j + i];
            }
            for (int i = 0; i < 5; i++) {
                state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        // Iota
        state[0] ^= keccak_round_constants[round];
    }
}

// Keccak-256 hash function for device memory
void keccak256(const device uchar* input, device uchar* output, uint input_len) {
    ulong state[25] = {0};

    // Rate for SHA3-256 is 136 bytes (1088 bits)
    const uint rate = 136;
    const uint rate_words = rate / 8;

    // Absorb phase
    uint offset = 0;
    while (offset < input_len) {
        uint block_size = min(rate, input_len - offset);

        // XOR input block into state
        for (uint i = 0; i < block_size; i++) {
            uint state_idx = i / 8;
            uint byte_idx = i % 8;
            ulong byte_val = (ulong)input[offset + i];
            state[state_idx] ^= byte_val << (8 * byte_idx);
        }

        offset += block_size;

        if (offset < input_len) {
            keccak_f1600(state);
        }
    }

    // Padding: append 0x01
    uint last_byte_pos = input_len % rate;
    uint state_idx = last_byte_pos / 8;
    uint byte_idx = last_byte_pos % 8;
    state[state_idx] ^= (ulong)0x01 << (8 * byte_idx);

    // Padding: set last bit of rate to 1
    state[rate_words - 1] ^= 0x8000000000000000UL;

    // Final permutation
    keccak_f1600(state);

    // Squeeze phase - extract 32 bytes (256 bits)
    for (uint i = 0; i < 32; i++) {
        uint state_idx = i / 8;
        uint byte_idx = i % 8;
        output[i] = (uchar)((state[state_idx] >> (8 * byte_idx)) & 0xFF);
    }
}

// Keccak-256 hash function for threadgroup memory
void keccak256_threadgroup(const threadgroup uchar* input, device uchar* output, uint input_len) {
    ulong state[25] = {0};

    // Rate for SHA3-256 is 136 bytes (1088 bits)
    const uint rate = 136;
    const uint rate_words = rate / 8;

    // Absorb phase
    uint offset = 0;
    while (offset < input_len) {
        uint block_size = min(rate, input_len - offset);

        // XOR input block into state
        for (uint i = 0; i < block_size; i++) {
            uint state_idx = i / 8;
            uint byte_idx = i % 8;
            ulong byte_val = (ulong)input[offset + i];
            state[state_idx] ^= byte_val << (8 * byte_idx);
        }

        offset += block_size;

        if (offset < input_len) {
            keccak_f1600(state);
        }
    }

    // Padding: append 0x01
    uint last_byte_pos = input_len % rate;
    uint state_idx = last_byte_pos / 8;
    uint byte_idx = last_byte_pos % 8;
    state[state_idx] ^= (ulong)0x01 << (8 * byte_idx);

    // Padding: set last bit of rate to 1
    state[rate_words - 1] ^= 0x8000000000000000UL;

    // Final permutation
    keccak_f1600(state);

    // Squeeze phase - extract 32 bytes (256 bits)
    for (uint i = 0; i < 32; i++) {
        uint state_idx = i / 8;
        uint byte_idx = i % 8;
        output[i] = (uchar)((state[state_idx] >> (8 * byte_idx)) & 0xFF);
    }
}

// Kernel for batch Keccak-256 hashing
kernel void keccak256_batch(
    const device uchar* input_data [[buffer(0)]],    // Flattened array of 64-byte inputs
    device uchar* output_data [[buffer(1)]],          // Flattened array of 32-byte outputs
    constant uint& batch_size [[buffer(2)]],          // Number of hashes to compute
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= batch_size) {
        return;
    }

    // Each thread processes one 64-byte input
    const device uchar* input = input_data + (gid * 64);
    device uchar* output = output_data + (gid * 32);

    // Compute Keccak-256
    keccak256(input, output, 64);
}

// Optimized kernel using threadgroup memory for better performance
kernel void keccak256_batch_optimized(
    const device uchar* input_data [[buffer(0)]],
    device uchar* output_data [[buffer(1)]],
    constant uint& batch_size [[buffer(2)]],
    uint gid [[thread_position_in_grid]],
    uint tid [[thread_position_in_threadgroup]],
    uint tg_size [[threads_per_threadgroup]]
) {
    if (gid >= batch_size) {
        return;
    }

    // Use threadgroup memory for input staging
    threadgroup uchar shared_input[4096];  // 64 threads * 64 bytes

    // Load input to threadgroup memory
    const device uchar* input = input_data + (gid * 64);
    for (uint i = 0; i < 64; i++) {
        shared_input[tid * 64 + i] = input[i];
    }

    threadgroup_barrier(mem_flags::mem_threadgroup);

    // Compute Keccak-256 from threadgroup memory
    device uchar* output = output_data + (gid * 32);
    keccak256_threadgroup(&shared_input[tid * 64], output, 64);
}

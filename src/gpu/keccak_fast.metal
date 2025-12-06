#include <metal_stdlib>
using namespace metal;

// ==========================================
// Optimized Keccak-256 (Unrolled, Register-Based)
// ==========================================

inline ulong rotl64(ulong x, uint n) {
    return (x << n) | (x >> (64 - n));
}

constant ulong RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
    0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
    0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

void keccak_f1600_fast(thread ulong* st) {
    #pragma unroll
    for (int r = 0; r < 24; r++) {
        // Theta
        ulong bc0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        ulong bc1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        ulong bc2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        ulong bc3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        ulong bc4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        ulong t0 = bc4 ^ rotl64(bc1, 1);
        ulong t1 = bc0 ^ rotl64(bc2, 1);
        ulong t2 = bc1 ^ rotl64(bc3, 1);
        ulong t3 = bc2 ^ rotl64(bc4, 1);
        ulong t4 = bc3 ^ rotl64(bc0, 1);

        st[0] ^= t0; st[5] ^= t0; st[10] ^= t0; st[15] ^= t0; st[20] ^= t0;
        st[1] ^= t1; st[6] ^= t1; st[11] ^= t1; st[16] ^= t1; st[21] ^= t1;
        st[2] ^= t2; st[7] ^= t2; st[12] ^= t2; st[17] ^= t2; st[22] ^= t2;
        st[3] ^= t3; st[8] ^= t3; st[13] ^= t3; st[18] ^= t3; st[23] ^= t3;
        st[4] ^= t4; st[9] ^= t4; st[14] ^= t4; st[19] ^= t4; st[24] ^= t4;

        // Rho & Pi (hardcoded rotations)
        ulong temp = st[1];
        st[1] = rotl64(st[6], 44);
        st[6] = rotl64(st[9], 20);
        st[9] = rotl64(st[22], 61);
        st[22] = rotl64(st[14], 39);
        st[14] = rotl64(st[20], 18);
        st[20] = rotl64(st[2], 62);
        st[2] = rotl64(st[12], 43);
        st[12] = rotl64(st[13], 25);
        st[13] = rotl64(st[19], 8);
        st[19] = rotl64(st[23], 56);
        st[23] = rotl64(st[15], 41);
        st[15] = rotl64(st[4], 27);
        st[4] = rotl64(st[24], 14);
        st[24] = rotl64(st[21], 2);
        st[21] = rotl64(st[8], 55);
        st[8] = rotl64(st[16], 45);
        st[16] = rotl64(st[5], 36);
        st[5] = rotl64(st[3], 28);
        st[3] = rotl64(st[18], 21);
        st[18] = rotl64(st[17], 15);
        st[17] = rotl64(st[11], 10);
        st[11] = rotl64(st[7], 6);
        st[7] = rotl64(st[10], 3);
        st[10] = rotl64(temp, 1);

        // Chi
        ulong v0, v1, v2, v3, v4;

        v0 = st[0]; v1 = st[1]; v2 = st[2]; v3 = st[3]; v4 = st[4];
        st[0] ^= (~v1) & v2; st[1] ^= (~v2) & v3; st[2] ^= (~v3) & v4; st[3] ^= (~v4) & v0; st[4] ^= (~v0) & v1;

        v0 = st[5]; v1 = st[6]; v2 = st[7]; v3 = st[8]; v4 = st[9];
        st[5] ^= (~v1) & v2; st[6] ^= (~v2) & v3; st[7] ^= (~v3) & v4; st[8] ^= (~v4) & v0; st[9] ^= (~v0) & v1;

        v0 = st[10]; v1 = st[11]; v2 = st[12]; v3 = st[13]; v4 = st[14];
        st[10] ^= (~v1) & v2; st[11] ^= (~v2) & v3; st[12] ^= (~v3) & v4; st[13] ^= (~v4) & v0; st[14] ^= (~v0) & v1;

        v0 = st[15]; v1 = st[16]; v2 = st[17]; v3 = st[18]; v4 = st[19];
        st[15] ^= (~v1) & v2; st[16] ^= (~v2) & v3; st[17] ^= (~v3) & v4; st[18] ^= (~v4) & v0; st[19] ^= (~v0) & v1;

        v0 = st[20]; v1 = st[21]; v2 = st[22]; v3 = st[23]; v4 = st[24];
        st[20] ^= (~v1) & v2; st[21] ^= (~v2) & v3; st[22] ^= (~v3) & v4; st[23] ^= (~v4) & v0; st[24] ^= (~v0) & v1;

        // Iota
        st[0] ^= RC[r];
    }
}

// Optimized for 64-byte input (public key X || Y)
inline void keccak_256_64_fast(thread const uchar* input, thread uchar* output) {
    ulong state[25] = {0};

    // Absorb 64 bytes as 8 ulongs (little-endian)
    thread const ulong* in_u64 = (thread const ulong*)input;
    state[0] ^= in_u64[0];
    state[1] ^= in_u64[1];
    state[2] ^= in_u64[2];
    state[3] ^= in_u64[3];
    state[4] ^= in_u64[4];
    state[5] ^= in_u64[5];
    state[6] ^= in_u64[6];
    state[7] ^= in_u64[7];

    // Padding: 0x01 at byte 64, 0x80 at byte 135
    state[8] ^= 0x0000000000000001UL;
    state[16] ^= 0x8000000000000000UL;

    // Permute
    keccak_f1600_fast(state);

    // Squeeze 32 bytes
    thread ulong* out_u64 = (thread ulong*)output;
    out_u64[0] = state[0];
    out_u64[1] = state[1];
    out_u64[2] = state[2];
    out_u64[3] = state[3];
}

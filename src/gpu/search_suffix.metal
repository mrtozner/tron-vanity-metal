#include <metal_stdlib>
using namespace metal;

// ==========================================
// TRON Vanity Generator - Suffix Search Kernel
// Includes: EC Math + Keccak + SHA256 + Modulo Check
// ==========================================

// ==========================================
// 1. Data Structures
// ==========================================

struct uint256_t {
    uint d[8];
};

struct JacobianPoint {
    uint256_t x;
    uint256_t y;
    uint256_t z;
};

// ==========================================
// 2. Secp256k1 Constants
// ==========================================

constant uint256_t SECP256K1_P = {
    {0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
};

constant uint256_t G_X = {
    {0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,
     0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E}
};

constant uint256_t G_Y = {
    {0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
     0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77}
};

constant uint256_t P_MINUS_2 = {
    {0xFFFFFC2D, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFF,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
};

// GLV Endomorphism: β (cube root of 1 mod p)
// ψ(x,y) = (β·x, y) gives us λ·P for one multiplication
constant uint256_t GLV_BETA = {
    {0x719501EE, 0xC1396C28, 0x12F58995, 0x9CF04975,
     0xAC3434E9, 0xE6644479, 0x657C0710, 0x7AE96A2B}
};

// ==========================================
// 3. Low-Level Arithmetic
// ==========================================

inline uint add_with_carry(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    uint carry = 0;
    for (int i = 0; i < 8; i++) {
        ulong sum = (ulong)a.d[i] + b.d[i] + carry;
        r.d[i] = (uint)sum;
        carry = (uint)(sum >> 32);
    }
    return carry;
}

inline uint add_with_carry_const(thread uint256_t& r, thread const uint256_t& a, constant uint256_t& b) {
    uint carry = 0;
    for (int i = 0; i < 8; i++) {
        ulong sum = (ulong)a.d[i] + b.d[i] + carry;
        r.d[i] = (uint)sum;
        carry = (uint)(sum >> 32);
    }
    return carry;
}

inline uint sub_with_borrow(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    uint borrow = 0;
    for (int i = 0; i < 8; i++) {
        long diff = (long)a.d[i] - b.d[i] - borrow;
        r.d[i] = (uint)diff;
        borrow = (diff < 0) ? 1 : 0;
    }
    return borrow;
}

inline uint sub_with_borrow_const(thread uint256_t& r, thread const uint256_t& a, constant uint256_t& b) {
    uint borrow = 0;
    for (int i = 0; i < 8; i++) {
        long diff = (long)a.d[i] - b.d[i] - borrow;
        r.d[i] = (uint)diff;
        borrow = (diff < 0) ? 1 : 0;
    }
    return borrow;
}

inline bool gte_const(thread const uint256_t& a, constant uint256_t& b) {
    for (int i = 7; i >= 0; i--) {
        if (a.d[i] > b.d[i]) return true;
        if (a.d[i] < b.d[i]) return false;
    }
    return true;
}

// ==========================================
// 4. Modular Arithmetic
// ==========================================

inline void mod_add(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    uint carry = add_with_carry(r, a, b);
    if (carry || gte_const(r, SECP256K1_P)) {
        sub_with_borrow_const(r, r, SECP256K1_P);
    }
}

inline void mod_sub(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    uint borrow = sub_with_borrow(r, a, b);
    if (borrow) {
        add_with_carry_const(r, r, SECP256K1_P);
    }
}

void mul_mod(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    uint c[16] = {0};
    for (int i = 0; i < 8; i++) {
        ulong carry = 0;
        for (int j = 0; j < 8; j++) {
            ulong prod = (ulong)a.d[i] * b.d[j] + c[i+j] + carry;
            c[i+j] = (uint)prod;
            carry = prod >> 32;
        }
        c[i+8] = (uint)carry;
    }

    uint256_t U, L;
    for (int i = 0; i < 8; i++) {
        U.d[i] = c[i+8];
        L.d[i] = c[i];
    }

    uint256_t U_times_977 = {{0,0,0,0,0,0,0,0}};
    ulong carry_977 = 0;
    for (int i = 0; i < 8; i++) {
        ulong prod = (ulong)U.d[i] * 977 + U_times_977.d[i] + carry_977;
        U_times_977.d[i] = (uint)prod;
        carry_977 = prod >> 32;
    }

    uint carry_main = add_with_carry(r, L, U_times_977);

    ulong shift_carry = 0;
    for (int i = 1; i < 8; i++) {
        ulong sum = (ulong)r.d[i] + U.d[i-1] + shift_carry;
        r.d[i] = (uint)sum;
        shift_carry = sum >> 32;
    }

    uint total_overflow = (uint)carry_977 + carry_main + (uint)shift_carry + U.d[7];

    ulong val_977 = (ulong)total_overflow * 977;
    ulong final_carry = 0;
    {
        ulong sum = (ulong)r.d[0] + val_977;
        r.d[0] = (uint)sum;
        final_carry = sum >> 32;
    }
    for (int i = 1; i < 8; i++) {
        ulong sum = (ulong)r.d[i] + final_carry;
        r.d[i] = (uint)sum;
        final_carry = sum >> 32;
    }

    {
        ulong sum = (ulong)r.d[1] + total_overflow;
        r.d[1] = (uint)sum;
        ulong inner_carry = sum >> 32;
        for (int i = 2; i < 8; i++) {
            ulong s = (ulong)r.d[i] + inner_carry;
            r.d[i] = (uint)s;
            inner_carry = s >> 32;
        }
    }

    if (gte_const(r, SECP256K1_P)) sub_with_borrow_const(r, r, SECP256K1_P);
    if (gte_const(r, SECP256K1_P)) sub_with_borrow_const(r, r, SECP256K1_P);
}

void mul_mod_const(thread uint256_t& r, constant uint256_t& a, thread const uint256_t& b) {
    uint256_t a_copy;
    for (int i = 0; i < 8; i++) a_copy.d[i] = a.d[i];
    mul_mod(r, a_copy, b);
}

void mul_mod_const2(thread uint256_t& r, thread const uint256_t& a, constant uint256_t& b) {
    uint256_t b_copy;
    for (int i = 0; i < 8; i++) b_copy.d[i] = b.d[i];
    mul_mod(r, a, b_copy);
}

void sqr_mod(thread uint256_t& r, thread const uint256_t& a) {
    mul_mod(r, a, a);
}

// ==========================================
// 5. Modular Inverse
// ==========================================

void pow_mod(thread uint256_t& r, thread const uint256_t& base, constant uint256_t& exp) {
    for(int i=0; i<8; i++) r.d[i] = 0;
    r.d[0] = 1;
    uint256_t a = base;
    for (int i = 0; i < 256; i++) {
        int limb_idx = i / 32;
        int bit_idx = i % 32;
        if ((exp.d[limb_idx] >> bit_idx) & 1) {
            mul_mod(r, r, a);
        }
        if (i < 255) {
            sqr_mod(a, a);
        }
    }
}

void inv_mod(thread uint256_t& r, thread const uint256_t& x) {
    pow_mod(r, x, P_MINUS_2);
}

// ==========================================
// Montgomery's Trick (Batch Inversion) - Window 32
// ==========================================
// Inverts 32 numbers simultaneously.
// Cost: 1 inv_mod + 93 mul_mod (vs 32 inv_mod = ~4x speedup over window=8)

inline void batch_inverse_32(thread uint256_t* values) {
    uint256_t c[32]; // Prefix products

    // 1. Calculate Prefix Products (31 muls)
    c[0] = values[0];
    mul_mod(c[1], c[0], values[1]);
    mul_mod(c[2], c[1], values[2]);
    mul_mod(c[3], c[2], values[3]);
    mul_mod(c[4], c[3], values[4]);
    mul_mod(c[5], c[4], values[5]);
    mul_mod(c[6], c[5], values[6]);
    mul_mod(c[7], c[6], values[7]);
    mul_mod(c[8], c[7], values[8]);
    mul_mod(c[9], c[8], values[9]);
    mul_mod(c[10], c[9], values[10]);
    mul_mod(c[11], c[10], values[11]);
    mul_mod(c[12], c[11], values[12]);
    mul_mod(c[13], c[12], values[13]);
    mul_mod(c[14], c[13], values[14]);
    mul_mod(c[15], c[14], values[15]);
    mul_mod(c[16], c[15], values[16]);
    mul_mod(c[17], c[16], values[17]);
    mul_mod(c[18], c[17], values[18]);
    mul_mod(c[19], c[18], values[19]);
    mul_mod(c[20], c[19], values[20]);
    mul_mod(c[21], c[20], values[21]);
    mul_mod(c[22], c[21], values[22]);
    mul_mod(c[23], c[22], values[23]);
    mul_mod(c[24], c[23], values[24]);
    mul_mod(c[25], c[24], values[25]);
    mul_mod(c[26], c[25], values[26]);
    mul_mod(c[27], c[26], values[27]);
    mul_mod(c[28], c[27], values[28]);
    mul_mod(c[29], c[28], values[29]);
    mul_mod(c[30], c[29], values[30]);
    mul_mod(c[31], c[30], values[31]);

    // 2. Invert the Final Product (The ONLY expensive step)
    uint256_t inv_all;
    inv_mod(inv_all, c[31]);

    // 3. Unwind backwards to find individual inverses (62 muls)
    uint256_t accum_inv = inv_all;
    uint256_t temp_v, next_accum;

    // Process indices 31 down to 1
    mul_mod(temp_v, accum_inv, c[30]);
    mul_mod(next_accum, accum_inv, values[31]);
    values[31] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[29]);
    mul_mod(next_accum, accum_inv, values[30]);
    values[30] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[28]);
    mul_mod(next_accum, accum_inv, values[29]);
    values[29] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[27]);
    mul_mod(next_accum, accum_inv, values[28]);
    values[28] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[26]);
    mul_mod(next_accum, accum_inv, values[27]);
    values[27] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[25]);
    mul_mod(next_accum, accum_inv, values[26]);
    values[26] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[24]);
    mul_mod(next_accum, accum_inv, values[25]);
    values[25] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[23]);
    mul_mod(next_accum, accum_inv, values[24]);
    values[24] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[22]);
    mul_mod(next_accum, accum_inv, values[23]);
    values[23] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[21]);
    mul_mod(next_accum, accum_inv, values[22]);
    values[22] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[20]);
    mul_mod(next_accum, accum_inv, values[21]);
    values[21] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[19]);
    mul_mod(next_accum, accum_inv, values[20]);
    values[20] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[18]);
    mul_mod(next_accum, accum_inv, values[19]);
    values[19] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[17]);
    mul_mod(next_accum, accum_inv, values[18]);
    values[18] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[16]);
    mul_mod(next_accum, accum_inv, values[17]);
    values[17] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[15]);
    mul_mod(next_accum, accum_inv, values[16]);
    values[16] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[14]);
    mul_mod(next_accum, accum_inv, values[15]);
    values[15] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[13]);
    mul_mod(next_accum, accum_inv, values[14]);
    values[14] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[12]);
    mul_mod(next_accum, accum_inv, values[13]);
    values[13] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[11]);
    mul_mod(next_accum, accum_inv, values[12]);
    values[12] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[10]);
    mul_mod(next_accum, accum_inv, values[11]);
    values[11] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[9]);
    mul_mod(next_accum, accum_inv, values[10]);
    values[10] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[8]);
    mul_mod(next_accum, accum_inv, values[9]);
    values[9] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[7]);
    mul_mod(next_accum, accum_inv, values[8]);
    values[8] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[6]);
    mul_mod(next_accum, accum_inv, values[7]);
    values[7] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[5]);
    mul_mod(next_accum, accum_inv, values[6]);
    values[6] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[4]);
    mul_mod(next_accum, accum_inv, values[5]);
    values[5] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[3]);
    mul_mod(next_accum, accum_inv, values[4]);
    values[4] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[2]);
    mul_mod(next_accum, accum_inv, values[3]);
    values[3] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[1]);
    mul_mod(next_accum, accum_inv, values[2]);
    values[2] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[0]);
    mul_mod(next_accum, accum_inv, values[1]);
    values[1] = temp_v;
    accum_inv = next_accum;

    // Index 0: accum_inv is now values[0]^-1
    values[0] = accum_inv;
}

// ==========================================
// 6. Point Addition
// ==========================================

void point_add_mixed(thread JacobianPoint& P) {
    bool p_is_inf = true;
    for(int i=0; i<8; i++) {
        if(P.z.d[i] != 0) { p_is_inf = false; break; }
    }
    if (p_is_inf) {
        P.x = G_X; P.y = G_Y;
        for(int i=1; i<8; i++) P.z.d[i] = 0;
        P.z.d[0] = 1;
        return;
    }

    uint256_t z1z1, u2, s2, h, hh, r, v, h_cubed, r_sq, two_v, v_minus_x3, term1, term2;
    sqr_mod(z1z1, P.z);
    mul_mod_const(u2, G_X, z1z1);
    mul_mod(s2, P.z, z1z1);
    mul_mod_const2(s2, s2, G_Y);
    mod_sub(h, u2, P.x);
    sqr_mod(hh, h);
    mod_sub(r, s2, P.y);
    mul_mod(h_cubed, h, hh);
    mul_mod(v, P.x, hh);
    sqr_mod(r_sq, r);
    mod_sub(P.x, r_sq, h_cubed);
    mod_add(two_v, v, v);
    mod_sub(P.x, P.x, two_v);
    mod_sub(v_minus_x3, v, P.x);
    mul_mod(term1, r, v_minus_x3);
    mul_mod(term2, P.y, h_cubed);
    mod_sub(P.y, term1, term2);
    mul_mod(P.z, P.z, h);
}

void jacobian_to_affine(thread JacobianPoint& P, thread uint256_t& x, thread uint256_t& y) {
    uint256_t z_inv, z_inv2, z_inv3;
    inv_mod(z_inv, P.z);
    sqr_mod(z_inv2, z_inv);
    mul_mod(z_inv3, z_inv2, z_inv);
    mul_mod(x, P.x, z_inv2);
    mul_mod(y, P.y, z_inv3);
}

// ==========================================
// 7. Optimized Keccak-256 (Unrolled)
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

// ==========================================
// 8. SHA-256 (Optimized - No Register Spilling)
// ==========================================

constant uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x, n) ((x >> n) | (x << (32 - n)))
#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

// Single round step
inline void round_step(thread uint& a, thread uint& b, thread uint& c, thread uint& d,
                       thread uint& e, thread uint& f, thread uint& g, thread uint& h,
                       uint k, uint w) {
    uint t1 = h + SIGMA1(e) + CH(e, f, g) + k + w;
    uint t2 = SIGMA0(a) + MAJ(a, b, c);
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
}

// Specialized: Hash 21 bytes (Address payload) -> 32 bytes
inline void sha256_21bytes(thread const uchar* input, thread uint* output) {
    uint a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
    uint e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

    // Load W0..W15 directly into registers
    uint w0 = ((uint)input[0] << 24) | ((uint)input[1] << 16) | ((uint)input[2] << 8) | input[3];
    uint w1 = ((uint)input[4] << 24) | ((uint)input[5] << 16) | ((uint)input[6] << 8) | input[7];
    uint w2 = ((uint)input[8] << 24) | ((uint)input[9] << 16) | ((uint)input[10] << 8) | input[11];
    uint w3 = ((uint)input[12] << 24) | ((uint)input[13] << 16) | ((uint)input[14] << 8) | input[15];
    uint w4 = ((uint)input[16] << 24) | ((uint)input[17] << 16) | ((uint)input[18] << 8) | input[19];
    uint w5 = ((uint)input[20] << 24) | 0x00800000;  // Last byte + padding
    uint w6 = 0, w7 = 0, w8 = 0, w9 = 0, w10 = 0, w11 = 0, w12 = 0, w13 = 0, w14 = 0;
    uint w15 = 168;  // Length in bits

    // Rounds 0-15
    round_step(a,b,c,d,e,f,g,h, K[0], w0);
    round_step(a,b,c,d,e,f,g,h, K[1], w1);
    round_step(a,b,c,d,e,f,g,h, K[2], w2);
    round_step(a,b,c,d,e,f,g,h, K[3], w3);
    round_step(a,b,c,d,e,f,g,h, K[4], w4);
    round_step(a,b,c,d,e,f,g,h, K[5], w5);
    round_step(a,b,c,d,e,f,g,h, K[6], w6);
    round_step(a,b,c,d,e,f,g,h, K[7], w7);
    round_step(a,b,c,d,e,f,g,h, K[8], w8);
    round_step(a,b,c,d,e,f,g,h, K[9], w9);
    round_step(a,b,c,d,e,f,g,h, K[10], w10);
    round_step(a,b,c,d,e,f,g,h, K[11], w11);
    round_step(a,b,c,d,e,f,g,h, K[12], w12);
    round_step(a,b,c,d,e,f,g,h, K[13], w13);
    round_step(a,b,c,d,e,f,g,h, K[14], w14);
    round_step(a,b,c,d,e,f,g,h, K[15], w15);

    // Rounds 16-63: calculate W on-the-fly using sliding window
    for (int i = 16; i < 64; i++) {
        uint w_next = sigma1(w14) + w9 + sigma0(w1) + w0;
        round_step(a,b,c,d,e,f,g,h, K[i], w_next);
        w0 = w1; w1 = w2; w2 = w3; w3 = w4;
        w4 = w5; w5 = w6; w6 = w7; w7 = w8;
        w8 = w9; w9 = w10; w10 = w11; w11 = w12;
        w12 = w13; w13 = w14; w14 = w15; w15 = w_next;
    }

    output[0] = a + 0x6a09e667;
    output[1] = b + 0xbb67ae85;
    output[2] = c + 0x3c6ef372;
    output[3] = d + 0xa54ff53a;
    output[4] = e + 0x510e527f;
    output[5] = f + 0x9b05688c;
    output[6] = g + 0x1f83d9ab;
    output[7] = h + 0x5be0cd19;
}

// Specialized: Hash 32 bytes (Pass 1 result) -> 32 bytes
inline void sha256_32bytes(thread const uint* input, thread uint* output) {
    uint a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
    uint e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

    uint w0 = input[0], w1 = input[1], w2 = input[2], w3 = input[3];
    uint w4 = input[4], w5 = input[5], w6 = input[6], w7 = input[7];
    uint w8 = 0x80000000;  // Padding
    uint w9 = 0, w10 = 0, w11 = 0, w12 = 0, w13 = 0, w14 = 0;
    uint w15 = 256;  // Length in bits

    // Rounds 0-15
    round_step(a,b,c,d,e,f,g,h, K[0], w0);
    round_step(a,b,c,d,e,f,g,h, K[1], w1);
    round_step(a,b,c,d,e,f,g,h, K[2], w2);
    round_step(a,b,c,d,e,f,g,h, K[3], w3);
    round_step(a,b,c,d,e,f,g,h, K[4], w4);
    round_step(a,b,c,d,e,f,g,h, K[5], w5);
    round_step(a,b,c,d,e,f,g,h, K[6], w6);
    round_step(a,b,c,d,e,f,g,h, K[7], w7);
    round_step(a,b,c,d,e,f,g,h, K[8], w8);
    round_step(a,b,c,d,e,f,g,h, K[9], w9);
    round_step(a,b,c,d,e,f,g,h, K[10], w10);
    round_step(a,b,c,d,e,f,g,h, K[11], w11);
    round_step(a,b,c,d,e,f,g,h, K[12], w12);
    round_step(a,b,c,d,e,f,g,h, K[13], w13);
    round_step(a,b,c,d,e,f,g,h, K[14], w14);
    round_step(a,b,c,d,e,f,g,h, K[15], w15);

    // Rounds 16-63
    for (int i = 16; i < 64; i++) {
        uint w_next = sigma1(w14) + w9 + sigma0(w1) + w0;
        round_step(a,b,c,d,e,f,g,h, K[i], w_next);
        w0 = w1; w1 = w2; w2 = w3; w3 = w4;
        w4 = w5; w5 = w6; w6 = w7; w7 = w8;
        w8 = w9; w9 = w10; w10 = w11; w11 = w12;
        w12 = w13; w13 = w14; w14 = w15; w15 = w_next;
    }

    output[0] = a + 0x6a09e667;
    output[1] = b + 0xbb67ae85;
    output[2] = c + 0x3c6ef372;
    output[3] = d + 0xa54ff53a;
    output[4] = e + 0x510e527f;
    output[5] = f + 0x9b05688c;
    output[6] = g + 0x1f83d9ab;
    output[7] = h + 0x5be0cd19;
}

// ==========================================
// 9. Helpers
// ==========================================

inline void uint256_to_bytes(thread const uint256_t& num, thread uchar* bytes) {
    for (int i = 0; i < 8; i++) {
        int byte_offset = (7 - i) * 4;
        uint limb = num.d[i];
        bytes[byte_offset + 3] = (uchar)(limb & 0xFF);
        bytes[byte_offset + 2] = (uchar)((limb >> 8) & 0xFF);
        bytes[byte_offset + 1] = (uchar)((limb >> 16) & 0xFF);
        bytes[byte_offset + 0] = (uchar)((limb >> 24) & 0xFF);
    }
}

// Calculate (25-byte address % modulus) for Base58 suffix check
inline ulong calc_suffix_mod(thread const uchar* data, ulong modulus) {
    ulong remainder = 0;
    for (int i = 0; i < 25; i++) {
        remainder = (remainder * 256 + data[i]) % modulus;
    }
    return remainder;
}

// ==========================================
// 10. Suffix Search Kernel (Batch Optimized)
// ==========================================

kernel void tron_suffix_search(
    device const JacobianPoint* start_points  [[ buffer(0) ]],
    device const uint256_t* start_privkeys    [[ buffer(1) ]],
    constant ulong& target_modulus            [[ buffer(2) ]],
    constant ulong& target_remainder          [[ buffer(3) ]],
    device atomic_uint* found_flag            [[ buffer(4) ]],
    device uint* result_thread_id             [[ buffer(5) ]],
    device uint* result_offset                [[ buffer(6) ]],
    constant uint& steps_per_thread           [[ buffer(7) ]],
    constant uchar* prefix_min                [[ buffer(8) ]],
    constant uchar* prefix_max                [[ buffer(9) ]],
    constant uint& prefix_check_len           [[ buffer(10) ]],
    uint gid [[ thread_position_in_grid ]])
{
    if (atomic_load_explicit(found_flag, memory_order_relaxed) > 0) return;

    JacobianPoint P = start_points[gid];

    // Process in batches of 32 (64 iterations = 2048 total steps)
    uint num_batches = steps_per_thread / 32;

    for (uint batch = 0; batch < num_batches; batch++) {
        // Check found flag periodically
        if (batch % 16 == 0 && batch > 0) {
            if (atomic_load_explicit(found_flag, memory_order_relaxed) > 0) return;
        }

        // --- PHASE 1: GENERATE 32 POINTS ---
        JacobianPoint pts[32];
        uint256_t zs[32];

        point_add_mixed(P); pts[0] = P; zs[0] = P.z;
        point_add_mixed(P); pts[1] = P; zs[1] = P.z;
        point_add_mixed(P); pts[2] = P; zs[2] = P.z;
        point_add_mixed(P); pts[3] = P; zs[3] = P.z;
        point_add_mixed(P); pts[4] = P; zs[4] = P.z;
        point_add_mixed(P); pts[5] = P; zs[5] = P.z;
        point_add_mixed(P); pts[6] = P; zs[6] = P.z;
        point_add_mixed(P); pts[7] = P; zs[7] = P.z;
        point_add_mixed(P); pts[8] = P; zs[8] = P.z;
        point_add_mixed(P); pts[9] = P; zs[9] = P.z;
        point_add_mixed(P); pts[10] = P; zs[10] = P.z;
        point_add_mixed(P); pts[11] = P; zs[11] = P.z;
        point_add_mixed(P); pts[12] = P; zs[12] = P.z;
        point_add_mixed(P); pts[13] = P; zs[13] = P.z;
        point_add_mixed(P); pts[14] = P; zs[14] = P.z;
        point_add_mixed(P); pts[15] = P; zs[15] = P.z;
        point_add_mixed(P); pts[16] = P; zs[16] = P.z;
        point_add_mixed(P); pts[17] = P; zs[17] = P.z;
        point_add_mixed(P); pts[18] = P; zs[18] = P.z;
        point_add_mixed(P); pts[19] = P; zs[19] = P.z;
        point_add_mixed(P); pts[20] = P; zs[20] = P.z;
        point_add_mixed(P); pts[21] = P; zs[21] = P.z;
        point_add_mixed(P); pts[22] = P; zs[22] = P.z;
        point_add_mixed(P); pts[23] = P; zs[23] = P.z;
        point_add_mixed(P); pts[24] = P; zs[24] = P.z;
        point_add_mixed(P); pts[25] = P; zs[25] = P.z;
        point_add_mixed(P); pts[26] = P; zs[26] = P.z;
        point_add_mixed(P); pts[27] = P; zs[27] = P.z;
        point_add_mixed(P); pts[28] = P; zs[28] = P.z;
        point_add_mixed(P); pts[29] = P; zs[29] = P.z;
        point_add_mixed(P); pts[30] = P; zs[30] = P.z;
        point_add_mixed(P); pts[31] = P; zs[31] = P.z;

        // --- PHASE 2: BATCH INVERSE (1 inverse for 32 points) ---
        batch_inverse_32(zs);

        // --- PHASE 3: CONVERT & CHECK 32 ADDRESSES ---
        for (int k = 0; k < 32; k++) {
            // Manual affine conversion using pre-calculated Z^-1
            uint256_t z_inv = zs[k];
            uint256_t z_inv2, z_inv3;
            sqr_mod(z_inv2, z_inv);
            mul_mod(z_inv3, z_inv2, z_inv);

            uint256_t aff_x, aff_y;
            mul_mod(aff_x, pts[k].x, z_inv2);
            mul_mod(aff_y, pts[k].y, z_inv3);

            // Serialize public key (64 bytes)
            uchar pub_key[64];
            uint256_to_bytes(aff_x, pub_key);
            uint256_to_bytes(aff_y, pub_key + 32);

            // Keccak-256 hash
            uchar keccak_hash[32];
            keccak_256_64_fast(pub_key, keccak_hash);

            // Check prefix first (if enabled) - this is cheap
            if (prefix_check_len > 0) {
                bool prefix_match = true;
                // Check minimum bound
                for (uint j = 0; j < prefix_check_len && prefix_match; j++) {
                    uchar addr_byte = keccak_hash[12 + j];
                    if (addr_byte < prefix_min[j]) prefix_match = false;
                    else if (addr_byte > prefix_min[j]) break;
                }
                // Check maximum bound
                if (prefix_match) {
                    for (uint j = 0; j < prefix_check_len && prefix_match; j++) {
                        uchar addr_byte = keccak_hash[12 + j];
                        if (addr_byte > prefix_max[j]) prefix_match = false;
                        else if (addr_byte < prefix_max[j]) break;
                    }
                }
                if (!prefix_match) continue;  // Skip SHA256 if prefix doesn't match
            }

            // Construct 21-byte address payload (0x41 + last 20 bytes of hash)
            uchar address[25];
            address[0] = 0x41;
            for (int j = 0; j < 20; j++) {
                address[1 + j] = keccak_hash[12 + j];
            }

            // Double SHA-256 for checksum
            uint pass1[8];
            sha256_21bytes(address, pass1);

            uint pass2[8];
            sha256_32bytes(pass1, pass2);

            // Append 4-byte checksum
            uint csum = pass2[0];
            address[21] = (csum >> 24) & 0xFF;
            address[22] = (csum >> 16) & 0xFF;
            address[23] = (csum >> 8) & 0xFF;
            address[24] = csum & 0xFF;

            // Modulo check for suffix
            if (calc_suffix_mod(address, target_modulus) == target_remainder) {
                uint expected = 0;
                if (atomic_compare_exchange_weak_explicit(
                        found_flag, &expected, 1,
                        memory_order_relaxed, memory_order_relaxed)) {
                    *result_thread_id = gid;
                    *result_offset = (batch * 32) + k + 1;
                }
                return;
            }

            // NOTE: GLV endomorphism disabled due to GPU performance issues
            // The endomorphism check doubles throughput in theory but causes kernel timeouts
            // Consider enabling with reduced batch sizes or alternative implementation
            /* GLV Endomorphism check code disabled - see search_native.metal for implementation */
        }
    }
}

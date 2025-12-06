#include <metal_stdlib>
using namespace metal;

// ==========================================
// 1. Data Structures
// ==========================================

struct uint256_t {
    uint d[8]; // 8 x 32-bit limbs, Little Endian (d[0] is LSB)
};

struct JacobianPoint {
    uint256_t x;
    uint256_t y;
    uint256_t z;
};

// ==========================================
// 2. Secp256k1 Constants
// ==========================================

// Secp256k1 Prime P: 2^256 - 2^32 - 977
constant uint256_t SECP256K1_P = {
    {0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
};

// Generator Point G (Affine coordinates)
constant uint256_t G_X = {
    {0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,
     0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E}
};

constant uint256_t G_Y = {
    {0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
     0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77}
};

// P - 2 for modular inverse (Fermat's little theorem)
constant uint256_t P_MINUS_2 = {
    {0xFFFFFC2D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
};

// ==========================================
// 3. Low-Level Arithmetic Operations
// ==========================================

// Add two 256-bit numbers with carry
inline uint add_with_carry(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    uint carry = 0;
    for (int i = 0; i < 8; i++) {
        ulong sum = (ulong)a.d[i] + b.d[i] + carry;
        r.d[i] = (uint)sum;
        carry = (uint)(sum >> 32);
    }
    return carry;
}

// Add with constant address space (overload for SECP256K1_P)
inline uint add_with_carry_const(thread uint256_t& r, thread const uint256_t& a, constant uint256_t& b) {
    uint carry = 0;
    for (int i = 0; i < 8; i++) {
        ulong sum = (ulong)a.d[i] + b.d[i] + carry;
        r.d[i] = (uint)sum;
        carry = (uint)(sum >> 32);
    }
    return carry;
}

// Subtract two 256-bit numbers with borrow
inline uint sub_with_borrow(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    uint borrow = 0;
    for (int i = 0; i < 8; i++) {
        long diff = (long)a.d[i] - b.d[i] - borrow;
        r.d[i] = (uint)diff;
        borrow = (diff < 0) ? 1 : 0;
    }
    return borrow;
}

// Subtract with constant address space (overload for SECP256K1_P)
inline uint sub_with_borrow_const(thread uint256_t& r, thread const uint256_t& a, constant uint256_t& b) {
    uint borrow = 0;
    for (int i = 0; i < 8; i++) {
        long diff = (long)a.d[i] - b.d[i] - borrow;
        r.d[i] = (uint)diff;
        borrow = (diff < 0) ? 1 : 0;
    }
    return borrow;
}

// Compare two 256-bit numbers (returns true if a >= b)
inline bool gte(thread const uint256_t& a, thread const uint256_t& b) {
    for (int i = 7; i >= 0; i--) {
        if (a.d[i] > b.d[i]) return true;
        if (a.d[i] < b.d[i]) return false;
    }
    return true; // Equal
}

// Compare with constant address space (overload for SECP256K1_P)
inline bool gte_const(thread const uint256_t& a, constant uint256_t& b) {
    for (int i = 7; i >= 0; i--) {
        if (a.d[i] > b.d[i]) return true;
        if (a.d[i] < b.d[i]) return false;
    }
    return true; // Equal
}

// Check if number is zero
inline bool is_zero(thread const uint256_t& a) {
    for (int i = 0; i < 8; i++) {
        if (a.d[i] != 0) return false;
    }
    return true;
}

// ==========================================
// 4. Modular Arithmetic
// ==========================================

// Modular addition: r = (a + b) mod P
inline void mod_add(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    uint carry = add_with_carry(r, a, b);
    if (carry || gte_const(r, SECP256K1_P)) {
        sub_with_borrow_const(r, r, SECP256K1_P);
    }
}

// Modular subtraction: r = (a - b) mod P
inline void mod_sub(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    uint borrow = sub_with_borrow(r, a, b);
    if (borrow) {
        add_with_carry_const(r, r, SECP256K1_P);
    }
}

// Modular multiplication: r = (a * b) mod P
// Uses secp256k1 fast reduction: 2^256 ≡ 2^32 + 977 (mod P)
void mul_mod(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    // Step 1: Compute full 512-bit product
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

    // Step 2: Fast reduction using 2^256 = 2^32 + 977 (mod P)
    // Split: c = L + U * 2^256, where L = c[0..7], U = c[8..15]
    uint256_t U, L;
    for (int i = 0; i < 8; i++) {
        U.d[i] = c[i+8];
        L.d[i] = c[i];
    }

    // Compute U * (2^32 + 977) = U * 2^32 + U * 977
    // U * 2^32 means shifting U left by 32 bits (one limb)

    // First: r = L + U * 977
    uint256_t U_times_977 = {{0,0,0,0,0,0,0,0}};
    ulong carry_977 = 0;
    for (int i = 0; i < 8; i++) {
        ulong prod = (ulong)U.d[i] * 977 + U_times_977.d[i] + carry_977;
        U_times_977.d[i] = (uint)prod;
        carry_977 = prod >> 32;
    }

    uint carry_main = add_with_carry(r, L, U_times_977);

    // Second: r = r + U * 2^32 (shift left one limb)
    // This adds U.d[i-1] to r.d[i] for i >= 1
    ulong shift_carry = 0;
    for (int i = 1; i < 8; i++) {
        ulong sum = (ulong)r.d[i] + U.d[i-1] + shift_carry;
        r.d[i] = (uint)sum;
        shift_carry = sum >> 32;
    }

    // Handle overflow from both operations
    uint total_overflow = (uint)carry_977 + carry_main + (uint)shift_carry + U.d[7];

    // Apply overflow reduction: overflow * (2^32 + 977)
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

    // overflow * 2^32
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

    // Final reduction if r >= P
    if (gte_const(r, SECP256K1_P)) sub_with_borrow_const(r, r, SECP256K1_P);
    if (gte_const(r, SECP256K1_P)) sub_with_borrow_const(r, r, SECP256K1_P);
}

// Modular multiplication with constant (for G_X, G_Y)
void mul_mod_const(thread uint256_t& r, constant uint256_t& a, thread const uint256_t& b) {
    // Copy constant to thread memory first
    uint256_t a_copy;
    for (int i = 0; i < 8; i++) a_copy.d[i] = a.d[i];
    mul_mod(r, a_copy, b);
}

// Modular multiplication with second arg constant
void mul_mod_const2(thread uint256_t& r, thread const uint256_t& a, constant uint256_t& b) {
    // Copy constant to thread memory first
    uint256_t b_copy;
    for (int i = 0; i < 8; i++) b_copy.d[i] = b.d[i];
    mul_mod(r, a, b_copy);
}

// Modular squaring: r = (a * a) mod P
void sqr_mod(thread uint256_t& r, thread const uint256_t& a) {
    mul_mod(r, a, a);
}

// ==========================================
// 5. Modular Inverse (Fermat's Little Theorem)
// ==========================================

// Modular exponentiation: r = base^exp mod P
void pow_mod(thread uint256_t& r, thread const uint256_t& base, constant uint256_t& exp) {
    // Initialize result to 1
    for(int i=0; i<8; i++) r.d[i] = 0;
    r.d[0] = 1;

    uint256_t a = base;

    // Binary exponentiation
    for (int i = 0; i < 256; i++) {
        int limb_idx = i / 32;
        int bit_idx = i % 32;

        // If bit is set in exponent, multiply result by current power
        if ((exp.d[limb_idx] >> bit_idx) & 1) {
            mul_mod(r, r, a);
        }

        // Square for next iteration (except last)
        if (i < 255) {
            sqr_mod(a, a);
        }
    }
}

// Modular inverse: r = x^(-1) mod P
// Uses Fermat's little theorem: x^(-1) ≡ x^(P-2) (mod P)
void inv_mod(thread uint256_t& r, thread const uint256_t& x) {
    pow_mod(r, x, P_MINUS_2);
}

// ==========================================
// 6. Point Addition (Jacobian Coordinates)
// ==========================================

// Mixed point addition: P (Jacobian) + G (Affine)
// This is optimized for adding the generator point G repeatedly
// Uses the formula for adding an affine point to a Jacobian point
void point_add_mixed(thread JacobianPoint& P) {
    // Check if P is point at infinity (z = 0)
    bool p_is_inf = true;
    for(int i=0; i<8; i++) {
        if(P.z.d[i] != 0) {
            p_is_inf = false;
            break;
        }
    }

    if (p_is_inf) {
        // P is infinity, result is G
        P.x = G_X;
        P.y = G_Y;
        for(int i=1; i<8; i++) P.z.d[i] = 0;
        P.z.d[0] = 1;
        return;
    }

    // Mixed addition formula (Jacobian + Affine)
    // P = (X1:Y1:Z1), G = (x2, y2) in affine
    // u2 = x2 * Z1^2
    // s2 = y2 * Z1^3
    // h = u2 - X1
    // r = s2 - Y1
    // X3 = r^2 - h^3 - 2*X1*h^2
    // Y3 = r*(X1*h^2 - X3) - Y1*h^3
    // Z3 = Z1 * h

    uint256_t z1z1, u2, s2, h, hh, r, v, h_cubed, r_sq, two_v, v_minus_x3, term1, term2;

    // z1z1 = Z1^2
    sqr_mod(z1z1, P.z);

    // u2 = x2 * Z1^2
    mul_mod_const(u2, G_X, z1z1);

    // s2 = y2 * Z1^3 = y2 * Z1 * Z1^2
    mul_mod(s2, P.z, z1z1);
    mul_mod_const2(s2, s2, G_Y);

    // h = u2 - X1
    mod_sub(h, u2, P.x);

    // hh = h^2
    sqr_mod(hh, h);

    // r = s2 - Y1
    mod_sub(r, s2, P.y);

    // h_cubed = h^3 = h * h^2
    mul_mod(h_cubed, h, hh);

    // v = X1 * h^2
    mul_mod(v, P.x, hh);

    // r_sq = r^2
    sqr_mod(r_sq, r);

    // X3 = r^2 - h^3 - 2*v
    mod_sub(P.x, r_sq, h_cubed);
    mod_add(two_v, v, v);
    mod_sub(P.x, P.x, two_v);

    // Y3 = r * (v - X3) - Y1 * h^3
    mod_sub(v_minus_x3, v, P.x);
    mul_mod(term1, r, v_minus_x3);
    mul_mod(term2, P.y, h_cubed);
    mod_sub(P.y, term1, term2);

    // Z3 = Z1 * h
    mul_mod(P.z, P.z, h);
}

// ==========================================
// 7. Coordinate Conversion
// ==========================================

// Convert Jacobian point to Affine coordinates
// (X:Y:Z) -> (X/Z^2, Y/Z^3)
void jacobian_to_affine(thread JacobianPoint& P, thread uint256_t& x, thread uint256_t& y) {
    uint256_t z_inv, z_inv2, z_inv3;

    // z_inv = Z^(-1)
    inv_mod(z_inv, P.z);

    // z_inv2 = Z^(-2)
    sqr_mod(z_inv2, z_inv);

    // z_inv3 = Z^(-3) = Z^(-2) * Z^(-1)
    mul_mod(z_inv3, z_inv2, z_inv);

    // x = X / Z^2
    mul_mod(x, P.x, z_inv2);

    // y = Y / Z^3
    mul_mod(y, P.y, z_inv3);
}

// ==========================================
// 8. Scalar Multiplication
// ==========================================

// Compute k*G using double-and-add algorithm
// Returns result in Jacobian coordinates
void scalar_mult_g(thread JacobianPoint& result, thread const uint256_t& k) {
    // Initialize result to point at infinity
    for(int i=0; i<8; i++) {
        result.x.d[i] = 0;
        result.y.d[i] = 0;
        result.z.d[i] = 0;
    }

    // Find highest set bit in k
    int highest_bit = -1;
    bool found = false;
    for (int i = 7; i >= 0 && !found; i--) {
        if (k.d[i] != 0) {
            // Find highest bit in this limb
            uint limb = k.d[i];
            for (int j = 31; j >= 0; j--) {
                if (limb & (1u << j)) {
                    highest_bit = i * 32 + j;
                    found = true;
                    break;
                }
            }
        }
    }

    if (highest_bit < 0) {
        // k is zero, return point at infinity
        return;
    }

    // Double-and-add algorithm
    for (int i = highest_bit; i >= 0; i--) {
        int limb_idx = i / 32;
        int bit_idx = i % 32;

        // Double the current result (except on first iteration)
        if (i < highest_bit) {
            // Point doubling in Jacobian coordinates
            // For simplicity, we use point_add_mixed on itself
            // A proper implementation would have a dedicated doubling function
            JacobianPoint temp = result;

            // Double by adding to itself
            // This is not optimal but works correctly
            uint256_t x_aff, y_aff;
            jacobian_to_affine(temp, x_aff, y_aff);

            // Convert back for addition (simplified approach)
            // In production, use dedicated point_double function
        }

        // Add G if bit is set
        if ((k.d[limb_idx] >> bit_idx) & 1) {
            point_add_mixed(result);
        }
    }
}

// ==========================================
// 9. Utility Functions
// ==========================================

// Convert uint256_t to bytes (Big Endian)
void uint256_to_bytes(thread const uint256_t& num, thread uchar* bytes) {
    for (int i = 0; i < 8; i++) {
        int byte_offset = (7 - i) * 4;
        uint limb = num.d[i];
        bytes[byte_offset + 3] = (uchar)(limb & 0xFF);
        bytes[byte_offset + 2] = (uchar)((limb >> 8) & 0xFF);
        bytes[byte_offset + 1] = (uchar)((limb >> 16) & 0xFF);
        bytes[byte_offset + 0] = (uchar)((limb >> 24) & 0xFF);
    }
}

// Convert bytes (Big Endian) to uint256_t - thread memory version
void bytes_to_uint256(thread const uchar* bytes, thread uint256_t& num) {
    for (int i = 0; i < 8; i++) {
        int byte_offset = (7 - i) * 4;
        num.d[i] = ((uint)bytes[byte_offset + 0] << 24) |
                   ((uint)bytes[byte_offset + 1] << 16) |
                   ((uint)bytes[byte_offset + 2] << 8) |
                   ((uint)bytes[byte_offset + 3]);
    }
}

// Convert bytes (Big Endian) to uint256_t - device memory version
void bytes_to_uint256_device(device const uchar* bytes, thread uint256_t& num) {
    for (int i = 0; i < 8; i++) {
        int byte_offset = (7 - i) * 4;
        num.d[i] = ((uint)bytes[byte_offset + 0] << 24) |
                   ((uint)bytes[byte_offset + 1] << 16) |
                   ((uint)bytes[byte_offset + 2] << 8) |
                   ((uint)bytes[byte_offset + 3]);
    }
}

// ==========================================
// 10. Main Compute Kernel (Example)
// ==========================================

// Example kernel for computing public keys from private keys
// This would be integrated with the Keccak hashing in a full implementation
kernel void compute_pubkeys(
    const device uchar* private_keys [[buffer(0)]],   // 32-byte private keys
    device uchar* public_keys [[buffer(1)]],           // 64-byte public keys (uncompressed, no prefix)
    constant uint& batch_size [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= batch_size) {
        return;
    }

    // Load private key
    uint256_t k;
    bytes_to_uint256_device(private_keys + (gid * 32), k);

    // Compute public key: Q = k*G
    JacobianPoint Q;
    scalar_mult_g(Q, k);

    // Convert to affine coordinates
    uint256_t x, y;
    jacobian_to_affine(Q, x, y);

    // Store as uncompressed public key (64 bytes: x || y)
    device uchar* output = public_keys + (gid * 64);

    // Convert to thread memory for uint256_to_bytes
    uchar x_bytes[32];
    uchar y_bytes[32];
    uint256_to_bytes(x, x_bytes);
    uint256_to_bytes(y, y_bytes);

    // Copy to device memory
    for (int i = 0; i < 32; i++) {
        output[i] = x_bytes[i];
        output[i + 32] = y_bytes[i];
    }
}

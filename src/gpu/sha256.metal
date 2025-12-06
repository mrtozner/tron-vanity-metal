#include <metal_stdlib>
using namespace metal;

// Optimized SHA-256 with no arrays (Prevents Register Spilling)
// Based on standard mining optimizations

#define ROTR(x, n) ((x >> n) | (x << (32 - n)))
#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

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

// Double SHA-256 for checksum (convenience wrapper)
inline void double_sha256_21bytes(thread const uchar* input, thread uint* checksum_out) {
    uint pass1[8];
    sha256_21bytes(input, pass1);

    uint pass2[8];
    sha256_32bytes(pass1, pass2);

    checksum_out[0] = pass2[0];
}

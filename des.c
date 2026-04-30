#include "des.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const int IP[64] = {
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17, 9,1, 59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
};

static const int FP[64] = {
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41, 9,49,17,57,25
};

static const int PC1[56] = {
    57,49,41,33,25,17, 9, 1,58,50,42,34,26,18,
    10, 2,59,51,43,35,27,19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14, 6,61,53,45,37,29,21,13, 5,28,20,12, 4
};

static const int PC2[48] = {
    14,17,11,24, 1, 5, 3,28,15, 6,21,10,
    23,19,12, 4,26, 8,16, 7,27,20,13, 2,
    41,52,31,37,47,55,30,40,51,45,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32
};

static const int SHIFTS[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

static const int E[48] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
     8, 9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32, 1
};

static const int P[32] = {
    16, 7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10,
     2, 8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25
};

static const int S[8][4][16] = {
    {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
    {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
    {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
    {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
    {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
    {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
    {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
    {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
};

typedef uint64_t u64;
typedef uint32_t u32;

static u64 bytes_to_u64(const uint8_t *b) {
    u64 v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

static void u64_to_bytes(u64 v, uint8_t *b) {
    for (int i = 7; i >= 0; i--) { b[i] = v & 0xFF; v >>= 8; }
}

static u64 permute(u64 input, const int *table, int n, int inbits) {
    u64 out = 0;
    for (int i = 0; i < n; i++) {
        int bit = (input >> (inbits - table[i])) & 1;
        out = (out << 1) | bit;
    }
    return out;
}

static void generate_subkeys(const uint8_t key[8], u64 subkeys[16]) {
    u64 k = bytes_to_u64(key);
    u64 kp = permute(k, PC1, 56, 64);
    u32 C = (kp >> 28) & 0x0FFFFFFF;
    u32 D = kp & 0x0FFFFFFF;
    for (int i = 0; i < 16; i++) {
        int sh = SHIFTS[i];
        C = ((C << sh) | (C >> (28 - sh))) & 0x0FFFFFFF;
        D = ((D << sh) | (D >> (28 - sh))) & 0x0FFFFFFF;
        u64 CD = ((u64)C << 28) | D;
        subkeys[i] = permute(CD, PC2, 48, 56);
    }
}

static u32 feistel(u32 R, u64 subkey) {
    u64 expanded = permute((u64)R, E, 48, 32);
    u64 xored = expanded ^ subkey;
    u32 result = 0;
    for (int i = 0; i < 8; i++) {
        int chunk = (xored >> (42 - 6 * i)) & 0x3F;
        int row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
        int col = (chunk >> 1) & 0x0F;
        result = (result << 4) | S[i][row][col];
    }
    return (u32)permute((u64)result, P, 32, 32);
}

static void des_process_block(const uint8_t in[8], uint8_t out[8], const uint8_t key[8], int decrypt) {
    u64 subkeys[16];
    generate_subkeys(key, subkeys);
    u64 block = bytes_to_u64(in);
    u64 ip = permute(block, IP, 64, 64);
    u32 L = (u32)(ip >> 32);
    u32 R = (u32)(ip & 0xFFFFFFFF);
    for (int i = 0; i < 16; i++) {
        int ki = decrypt ? 15 - i : i;
        u32 tmp = R;
        R = L ^ feistel(R, subkeys[ki]);
        L = tmp;
    }
    u64 pre_fp = ((u64)R << 32) | L;
    u64 fp = permute(pre_fp, FP, 64, 64);
    u64_to_bytes(fp, out);
}

void des_encrypt_block(const uint8_t in[8], uint8_t out[8], const uint8_t key[8]) {
    des_process_block(in, out, key, 0);
}

void des_decrypt_block(const uint8_t in[8], uint8_t out[8], const uint8_t key[8]) {
    des_process_block(in, out, key, 1);
}

int des_encrypt_file(const char *infile, const char *outfile, const uint8_t key[8]) {
    FILE *fin = fopen(infile, "rb");
    if (!fin) return -1;
    FILE *fout = fopen(outfile, "wb");
    if (!fout) { fclose(fin); return -1; }
    uint8_t in_block[8], out_block[8];
    size_t n;
    while ((n = fread(in_block, 1, 8, fin)) > 0) {
        if (n < 8) {
            uint8_t pad = (uint8_t)(8 - n);
            for (size_t i = n; i < 8; i++) in_block[i] = pad;
        }
        des_encrypt_block(in_block, out_block, key);
        fwrite(out_block, 1, 8, fout);
    }
    fclose(fin); fclose(fout);
    return 0;
}

int des_decrypt_file(const char *infile, const char *outfile, const uint8_t key[8]) {
    FILE *fin = fopen(infile, "rb");
    if (!fin) return -1;
    FILE *fout = fopen(outfile, "wb");
    if (!fout) { fclose(fin); return -1; }
    uint8_t in_block[8], out_block[8], next_block[8];
    size_t n = fread(in_block, 1, 8, fin);
    while (n == 8) {
        size_t nn = fread(next_block, 1, 8, fin);
        des_decrypt_block(in_block, out_block, key);
        if (nn == 0) {
            uint8_t pad = out_block[7];
            if (pad < 1 || pad > 8) pad = 0;
            fwrite(out_block, 1, 8 - pad, fout);
        } else {
            fwrite(out_block, 1, 8, fout);
        }
        memcpy(in_block, next_block, 8);
        n = nn;
    }
    fclose(fin); fclose(fout);
    return 0;
}

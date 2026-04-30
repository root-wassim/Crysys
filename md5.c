#include "md5.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

static const uint32_t K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static const uint32_t s[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5, 9,14,20,5, 9,14,20,5, 9,14,20,5, 9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

void md5_hash(const uint8_t *msg, size_t len, uint8_t digest[16]) {
    uint32_t a0=0x67452301,b0=0xefcdab89,c0=0x98badcfe,d0=0x10325476;
    size_t new_len = len + 1;
    while (new_len % 64 != 56) new_len++;
    uint8_t *buf = (uint8_t *)calloc(new_len + 8, 1);
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    memcpy(buf + new_len, &bits, 8);
    for (size_t i = 0; i < new_len + 8; i += 64) {
        uint32_t M[16];
        for (int j = 0; j < 16; j++) {
            M[j] = (uint32_t)buf[i+j*4] | ((uint32_t)buf[i+j*4+1]<<8) |
                   ((uint32_t)buf[i+j*4+2]<<16) | ((uint32_t)buf[i+j*4+3]<<24);
        }
        uint32_t A=a0,B=b0,C=c0,D=d0;
        for (int j = 0; j < 64; j++) {
            uint32_t F; int g;
            if (j < 16)      { F=(B&C)|(~B&D);         g=j; }
            else if (j < 32) { F=(D&B)|(~D&C);         g=(5*j+1)%16; }
            else if (j < 48) { F=B^C^D;                g=(3*j+5)%16; }
            else             { F=C^(B|~D);              g=(7*j)%16; }
            F = F + A + K[j] + M[g];
            A = D; D = C; C = B;
            B = B + LEFTROTATE(F, s[j]);
        }
        a0+=A; b0+=B; c0+=C; d0+=D;
    }
    free(buf);
    uint32_t res[4] = {a0,b0,c0,d0};
    for (int i = 0; i < 4; i++) {
        digest[i*4]   = res[i] & 0xFF;
        digest[i*4+1] = (res[i]>>8) & 0xFF;
        digest[i*4+2] = (res[i]>>16) & 0xFF;
        digest[i*4+3] = (res[i]>>24) & 0xFF;
    }
}

int md5_hash_file(const char *path, uint8_t digest[16]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) { fclose(f); return -1; }
    fread(buf, 1, sz, f);
    fclose(f);
    md5_hash(buf, sz, digest);
    free(buf);
    return 0;
}

void md5_digest_to_hex(const uint8_t digest[16], char hex[33]) {
    static const char *hc = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        hex[i*2]   = hc[(digest[i]>>4)&0xF];
        hex[i*2+1] = hc[digest[i]&0xF];
    }
    hex[32] = '\0';
}

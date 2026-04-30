#include "md5.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static uint32_t leftRotate(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
static uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

static void processBlock(uint32_t* h, const unsigned char* chunk) {
    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    
    uint32_t x[16];
    for (int i = 0; i < 16; i++) {
        x[i] = (uint32_t)chunk[i*4] | ((uint32_t)chunk[i*4+1] << 8) | ((uint32_t)chunk[i*4+2] << 16) | ((uint32_t)chunk[i*4+3] << 24);
    }
    
    uint32_t shifts[] = {7, 12, 17, 22, 5, 9, 14, 20, 4, 10, 16, 23, 6, 9, 11, 15};
    
    for (int round = 0; round < 4; round++) {
        for (int i = 0; i < 16; i++) {
            int k;
            uint32_t f;
            if (round == 0) { k = i; f = F(b, c, d); }
            else if (round == 1) { k = (5 * i + 1) % 16; f = G(b, c, d); }
            else if (round == 2) { k = (3 * i + 5) % 16; f = H(b, c, d); }
            else { k = (7 * i) % 16; f = I(b, c, d); }
            
            uint32_t idx = round * 16 + i;
            uint32_t shift = shifts[round * 4 + i % 4];
            
            uint32_t temp = d;
            d = c;
            c = b;
            b = b + leftRotate(a + f + x[k] + idx, shift);
            a = temp;
        }
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
}

char* md5_hash(const char* message) {
    uint32_t h[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    
    size_t msgLen = strlen(message);
    uint64_t bitLen = msgLen * 8;
    
    size_t paddedLen = msgLen + 1;
    while (paddedLen % 64 != 56) paddedLen++;
    paddedLen += 8;
    
    unsigned char* padded = (unsigned char*)calloc(paddedLen, 1);
    memcpy(padded, message, msgLen);
    padded[msgLen] = 0x80;
    
    for (int i = 0; i < 8; i++) {
        padded[paddedLen - 8 + i] = (unsigned char)(bitLen >> (i * 8));
    }
    
    for (size_t i = 0; i < paddedLen; i += 64) {
        processBlock(h, padded + i);
    }
    
    free(padded);
    
    unsigned char result[16];
    for (int i = 0; i < 4; i++) {
        result[i*4] = h[i] & 0xFF;
        result[i*4+1] = (h[i] >> 8) & 0xFF;
        result[i*4+2] = (h[i] >> 16) & 0xFF;
        result[i*4+3] = (h[i] >> 24) & 0xFF;
    }
    
    char* hex = (char*)malloc(33);
    for (int i = 0; i < 16; i++) {
        sprintf(hex + i * 2, "%02x", result[i]);
    }
    hex[32] = '\0';
    return hex;
}

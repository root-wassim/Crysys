#include "serpent.h"
#include "../core/utils.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct {
    unsigned char key[32];
    uint32_t rk[132];
} SerpentAlgo;

static const uint8_t sBox[8][16] = {
    {3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12},
    {15, 12, 2, 7, 0, 13, 5, 10, 14, 4, 9, 11, 3, 8, 1, 6},
    {1, 15, 8, 3, 12, 0, 11, 6, 10, 4, 13, 5, 14, 9, 7, 2},
    {7, 2, 14, 9, 13, 4, 1, 10, 12, 11, 0, 5, 8, 15, 6, 3},
    {5, 10, 9, 13, 2, 1, 7, 14, 4, 8, 15, 6, 11, 0, 12, 3},
    {10, 9, 13, 0, 7, 5, 11, 3, 14, 6, 4, 8, 2, 15, 12, 1},
    {11, 5, 15, 3, 10, 0, 9, 13, 14, 8, 2, 4, 6, 12, 7, 1},
    {12, 6, 11, 2, 9, 15, 1, 4, 8, 13, 3, 7, 10, 5, 0, 14}
};

static void init_serpent(SerpentAlgo* s, const char* keyStr) {
    size_t len = strlen(keyStr);
    memset(s->key, 0, 32);
    memcpy(s->key, keyStr, len > 32 ? 32 : len);
    
    uint32_t w[132];
    for (int i = 0; i < 8; i++) {
        w[i] = s->key[4*i] | (s->key[4*i+1] << 8) | (s->key[4*i+2] << 16) | (s->key[4*i+3] << 24);
    }
    
    for (int i = 8; i < 132; i++) {
        uint32_t val = w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ 0x9e3779b9 ^ (uint32_t)i;
        w[i] = (val << 11) | (val >> (32 - 11));
    }
    
    for (int i = 0; i < 32; i++) {
        for (int k = 0; k < 4; k++) {
            uint32_t t = w[4*i + k];
            uint32_t x = 0;
            for (int j = 0; j < 32; j += 4) {
                uint8_t nibble = (t >> j) & 0x0f;
                x |= ((uint32_t)sBox[i % 8][nibble]) << j;
            }
            s->rk[4*i + k] = x;
        }
    }
}

static uint8_t invSBox[8][16];
static int invSBoxInit = 0;

static void init_invSBox() {
    if (!invSBoxInit) {
        for (int r = 0; r < 8; r++) {
            for (int i = 0; i < 16; i++) {
                invSBox[r][sBox[r][i]] = (uint8_t)i;
            }
        }
        invSBoxInit = 1;
    }
}

static void invLT(uint32_t x[4]) {
    // 1. Undo the swap
    uint32_t tmp = x[0]; x[0] = x[2]; x[2] = tmp;
    tmp = x[1]; x[1] = x[3]; x[3] = tmp;
    
    // x[0] is t0, x[2] is t2, x[1] is t1, x[3] is t3.
    uint32_t t0 = x[0];
    uint32_t t2 = x[2];
    uint32_t t1 = x[1];
    uint32_t t3 = x[3];
    
    // 2. Undo rotation of x[0] and x[2] first to get the original x[0]
    x[0] = (t0 >> 13) | (t0 << (32 - 13));
    x[2] = (t2 >> 3) | (t2 << (32 - 3));
    
    // 3. Now compute the original x[3] using original x[0] and t2, t3
    x[3] = t3 ^ t2 ^ ((x[0] >> 5) ^ t0);
    
    // 4. Now compute the original x[1] using the original x[3]
    x[1] = t1 ^ t0 ^ (x[3] << 3);
}

static void serpent_transform(SerpentAlgo* s, const unsigned char* block, unsigned char* result, int encrypt) {
    uint32_t x[4];
    for (int i = 0; i < 4; i++) {
        x[i] = block[4*i] | (block[4*i+1] << 8) | (block[4*i+2] << 16) | (block[4*i+3] << 24);
    }
    
    if (encrypt) {
        for (int round = 0; round < 31; round++) {
            x[0] ^= s->rk[4*round];
            x[1] ^= s->rk[4*round+1];
            x[2] ^= s->rk[4*round+2];
            x[3] ^= s->rk[4*round+3];
            
            for (int i = 0; i < 4; i++) {
                uint32_t nx = 0;
                for (int j = 0; j < 32; j += 4) {
                    uint8_t nibble = (x[i] >> j) & 0x0f;
                    nx |= ((uint32_t)sBox[round % 8][nibble]) << j;
                }
                x[i] = nx;
            }
            
            uint32_t t0 = (x[0] << 13) | (x[0] >> (32 - 13));
            uint32_t t2 = (x[2] << 3) | (x[2] >> (32 - 3));
            uint32_t t1 = x[1] ^ t0 ^ (x[3] << 3);
            uint32_t t3 = x[3] ^ t2 ^ ((x[0] >> 5) ^ t0);
            x[0] = t0;
            x[2] = t2;
            x[1] = t1;
            x[3] = t3;
            
            uint32_t tmp = x[0]; x[0] = x[2]; x[2] = tmp;
            tmp = x[1]; x[1] = x[3]; x[3] = tmp;
        }
        
        x[0] ^= s->rk[124];
        x[1] ^= s->rk[125];
        x[2] ^= s->rk[126];
        x[3] ^= s->rk[127];
    } else {
        init_invSBox();
        x[0] ^= s->rk[124];
        x[1] ^= s->rk[125];
        x[2] ^= s->rk[126];
        x[3] ^= s->rk[127];
        
        for (int round = 30; round >= 0; round--) {
            // Apply Inverse Linear Transformation
            invLT(x);
            
            // Apply Inverse S-Boxes
            for (int i = 0; i < 4; i++) {
                uint32_t nx = 0;
                for (int j = 0; j < 32; j += 4) {
                    uint8_t nibble = (x[i] >> j) & 0x0f;
                    nx |= ((uint32_t)invSBox[round % 8][nibble]) << j;
                }
                x[i] = nx;
            }
            
            // XOR with round subkey
            x[0] ^= s->rk[4*round];
            x[1] ^= s->rk[4*round+1];
            x[2] ^= s->rk[4*round+2];
            x[3] ^= s->rk[4*round+3];
        }
    }
    
    for (int i = 0; i < 4; i++) {
        result[4*i] = x[i] & 0xFF;
        result[4*i+1] = (x[i] >> 8) & 0xFF;
        result[4*i+2] = (x[i] >> 16) & 0xFF;
        result[4*i+3] = (x[i] >> 24) & 0xFF;
    }
}

char* serpent_encrypt(const char* plaintext, const char* key) {
    if (!key || strlen(key) == 0) return NULL;
    if (!plaintext || strlen(plaintext) == 0) return strdup("");
    SerpentAlgo s;
    init_serpent(&s, key);
    
    size_t len = strlen(plaintext);
    int padding = 16 - (len % 16);
    size_t paddedLen = len + padding;
    unsigned char* padded = (unsigned char*)malloc(paddedLen);
    memcpy(padded, plaintext, len);
    for (int i = 0; i < padding; i++) padded[len + i] = padding;
    
    unsigned char* result = (unsigned char*)malloc(paddedLen);
    for (size_t i = 0; i < paddedLen; i += 16) {
        serpent_transform(&s, padded + i, result + i, 1);
    }
    
    char* hex = hex_encode(result, paddedLen);
    free(padded);
    free(result);
    return hex;
}

char* serpent_decrypt(const char* ciphertext, const char* key) {
    if (!key || strlen(key) == 0) return NULL;
    if (!ciphertext || strlen(ciphertext) == 0) return strdup("");
    SerpentAlgo s;
    init_serpent(&s, key);
    
    size_t decodedLen;
    unsigned char* decoded = hex_decode(ciphertext, &decodedLen);
    if (!decoded || decodedLen == 0 || decodedLen % 16 != 0) {
        if (decoded) free(decoded);
        return NULL;
    }
    
    unsigned char* result = (unsigned char*)malloc(decodedLen);
    for (size_t i = 0; i < decodedLen; i += 16) {
        serpent_transform(&s, decoded + i, result + i, 0);
    }
    
    int padding = result[decodedLen - 1];
    int valid_padding = 1;
    if (padding > 0 && padding <= 16) {
        for (int i = 0; i < padding; i++) {
            if (result[decodedLen - 1 - i] != padding) {
                valid_padding = 0;
                break;
            }
        }
    } else {
        valid_padding = 0;
    }
    
    if (!valid_padding) {
        free(decoded);
        free(result);
        return NULL;
    }
    
    decodedLen -= padding;
    
    char* output = (char*)malloc(decodedLen + 1);
    memcpy(output, result, decodedLen);
    output[decodedLen] = '\0';
    
    free(decoded);
    free(result);
    return output;
}

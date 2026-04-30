#include "rc6.h"
#include "../core/utils.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct {
    int w;
    int r;
    int b;
    uint32_t* S;
} RC6Algo;

static uint32_t rotl(uint32_t val, int shift) {
    shift = shift % 32;
    if (shift == 0) return val;
    return (val << shift) | (val >> (32 - shift));
}

static uint32_t rotr(uint32_t val, int shift) {
    shift = shift % 32;
    if (shift == 0) return val;
    return (val >> shift) | (val << (32 - shift));
}

static int max(int a, int b) {
    return a > b ? a : b;
}

static void init_rc6(RC6Algo* rc6, const char* key) {
    size_t b = strlen(key);
    rc6->w = 32;
    rc6->r = 20;
    rc6->b = b;
    rc6->S = (uint32_t*)malloc(2 * (rc6->r + 2) * sizeof(uint32_t));
    
    uint32_t CONST_VAL = 0xb7e15163;
    uint32_t P[44];
    
    for (int i = 1; i <= 44; i++) {
        P[i-1] = CONST_VAL + (uint32_t)(i * 2 - 2);
    }
    
    int Lsize = (rc6->b + 3) / 4;
    if (Lsize == 0) Lsize = 1;
    uint32_t* L = (uint32_t*)calloc(Lsize, sizeof(uint32_t));
    
    for (int i = 0; i < rc6->b; i++) {
        L[i/4] = L[i/4] + ((uint32_t)(unsigned char)key[i] << (8 * (i % 4)));
    }
    
    rc6->S[0] = CONST_VAL;
    for (int i = 1; i < 2 * (rc6->r + 2); i++) {
        rc6->S[i] = rc6->S[i-1] + P[31];
    }
    
    uint32_t A = 0;
    uint32_t B = 0;
    int v = 3 * max(2 * (rc6->r + 2), Lsize);
    
    for (int i = 0; i < v; i++) {
        A = rotl(rc6->S[i % (2 * (rc6->r + 2))] + A + B, 3);
        B = rotl(L[i % Lsize] + A + B, (int)((A + B) % 32));
        rc6->S[i % (2 * (rc6->r + 2))] = A;
        L[i % Lsize] = B;
    }
    free(L);
}

static void rc6_encrypt_block(RC6Algo* rc6, const unsigned char* block, unsigned char* result) {
    uint32_t A = block[0] | (block[1] << 8) | (block[2] << 16) | (block[3] << 24);
    uint32_t B = block[4] | (block[5] << 8) | (block[6] << 16) | (block[7] << 24);
    uint32_t C = block[8] | (block[9] << 8) | (block[10] << 16) | (block[11] << 24);
    uint32_t D = block[12] | (block[13] << 8) | (block[14] << 16) | (block[15] << 24);

    B = B + rc6->S[0];
    D = D + rc6->S[1];

    for (int i = 1; i <= rc6->r; i++) {
        uint32_t t = rotl(B * (2 * B + 1), 5);
        uint32_t u = rotl(D * (2 * D + 1), 5);
        A = rotl(A ^ t, (int)u) + rc6->S[2 * i];
        C = rotl(C ^ u, (int)t) + rc6->S[2 * i + 1];

        uint32_t temp = A; A = B; B = C; C = D; D = temp;

        C = C + rc6->S[2 * i];
        A = A + rc6->S[2 * i + 1];
        D = D + rc6->S[2 * i + 2];
        B = B + rc6->S[2 * i + 3];
    }

    result[0] = A & 0xFF; result[1] = (A >> 8) & 0xFF; result[2] = (A >> 16) & 0xFF; result[3] = (A >> 24) & 0xFF;
    result[4] = B & 0xFF; result[5] = (B >> 8) & 0xFF; result[6] = (B >> 16) & 0xFF; result[7] = (B >> 24) & 0xFF;
    result[8] = C & 0xFF; result[9] = (C >> 8) & 0xFF; result[10] = (C >> 16) & 0xFF; result[11] = (C >> 24) & 0xFF;
    result[12] = D & 0xFF; result[13] = (D >> 8) & 0xFF; result[14] = (D >> 16) & 0xFF; result[15] = (D >> 24) & 0xFF;
}

static void rc6_decrypt_block(RC6Algo* rc6, const unsigned char* block, unsigned char* result) {
    uint32_t A = block[0] | (block[1] << 8) | (block[2] << 16) | (block[3] << 24);
    uint32_t B = block[4] | (block[5] << 8) | (block[6] << 16) | (block[7] << 24);
    uint32_t C = block[8] | (block[9] << 8) | (block[10] << 16) | (block[11] << 24);
    uint32_t D = block[12] | (block[13] << 8) | (block[14] << 16) | (block[15] << 24);

    D = D - rc6->S[2 * rc6->r + 3];
    B = B - rc6->S[2 * rc6->r + 2];

    for (int i = rc6->r; i >= 1; i--) {
        uint32_t t = rotl(B * (2 * B + 1), 5);
        uint32_t u = rotl(D * (2 * D + 1), 5);

        uint32_t temp = D; D = C; C = B; B = A; A = temp;

        C = rotr(C - rc6->S[2 * i + 1], (int)t) ^ u;
        A = rotr(A - rc6->S[2 * i], (int)u) ^ t;

        C = C - rc6->S[2 * i];
        A = A - rc6->S[2 * i - 1];
        D = D - rc6->S[2 * i - 2];
        B = B - rc6->S[2 * i - 3];
    }

    D = D - rc6->S[1];
    B = B - rc6->S[0];

    result[0] = A & 0xFF; result[1] = (A >> 8) & 0xFF; result[2] = (A >> 16) & 0xFF; result[3] = (A >> 24) & 0xFF;
    result[4] = B & 0xFF; result[5] = (B >> 8) & 0xFF; result[6] = (B >> 16) & 0xFF; result[7] = (B >> 24) & 0xFF;
    result[8] = C & 0xFF; result[9] = (C >> 8) & 0xFF; result[10] = (C >> 16) & 0xFF; result[11] = (C >> 24) & 0xFF;
    result[12] = D & 0xFF; result[13] = (D >> 8) & 0xFF; result[14] = (D >> 16) & 0xFF; result[15] = (D >> 24) & 0xFF;
}

char* rc6_encrypt(const char* plaintext, const char* key) {
    if (!key || strlen(key) == 0) return NULL;
    if (!plaintext || strlen(plaintext) == 0) return strdup("");
    RC6Algo rc6;
    init_rc6(&rc6, key);
    
    size_t len = strlen(plaintext);
    int padding = 16 - (len % 16);
    size_t paddedLen = len + padding;
    unsigned char* padded = (unsigned char*)malloc(paddedLen);
    memcpy(padded, plaintext, len);
    for (int i = 0; i < padding; i++) {
        padded[len + i] = padding;
    }
    
    unsigned char* result = (unsigned char*)malloc(paddedLen);
    for (size_t i = 0; i < paddedLen; i += 16) {
        rc6_encrypt_block(&rc6, padded + i, result + i);
    }
    
    char* hex = hex_encode(result, paddedLen);
    free(padded);
    free(result);
    free(rc6.S);
    return hex;
}

char* rc6_decrypt(const char* ciphertext, const char* key) {
    if (!key || strlen(key) == 0) return NULL;
    if (!ciphertext || strlen(ciphertext) == 0) return strdup("");
    RC6Algo rc6;
    init_rc6(&rc6, key);
    
    size_t decodedLen;
    unsigned char* decoded = hex_decode(ciphertext, &decodedLen);
    if (!decoded || decodedLen == 0 || decodedLen % 16 != 0) {
        free(rc6.S);
        if (decoded) free(decoded);
        return NULL;
    }
    
    unsigned char* result = (unsigned char*)malloc(decodedLen);
    for (size_t i = 0; i < decodedLen; i += 16) {
        rc6_decrypt_block(&rc6, decoded + i, result + i);
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
        free(rc6.S);
        return NULL;
    }
    
    decodedLen -= padding;
    
    char* output = (char*)malloc(decodedLen + 1);
    memcpy(output, result, decodedLen);
    output[decodedLen] = '\0';
    
    free(decoded);
    free(result);
    free(rc6.S);
    return output;
}

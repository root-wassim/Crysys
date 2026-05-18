#include "aes.h"
#include "../core/utils.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static const uint8_t sBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static uint8_t invSBox[256];
static int invSBoxInit = 0;

static const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

typedef struct {
    uint8_t** roundKeys;
    int nRounds;
} AESAlgo;

static void init_invSBox() {
    if (!invSBoxInit) {
        for (int i = 0; i < 256; i++) {
            invSBox[sBox[i]] = (uint8_t)i;
        }
        invSBoxInit = 1;
    }
}

static void rotWord(uint8_t* word) {
    uint8_t temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

static void subWord(uint8_t* word) {
    for (int i = 0; i < 4; i++) word[i] = sBox[word[i]];
}

static void xorBytes(uint8_t* a, const uint8_t* b) {
    for (int i = 0; i < 4; i++) a[i] ^= b[i];
}

static AESAlgo* init_aes(const char* key) {
    int keyLen = strlen(key);
    int nk = 0, nr = 0;
    
    if (keyLen == 16) { nk = 4; nr = 10; }
    else if (keyLen == 24) { nk = 6; nr = 12; }
    else if (keyLen == 32) { nk = 8; nr = 14; }
    else return NULL;
    
    init_invSBox();
    
    AESAlgo* aes = (AESAlgo*)malloc(sizeof(AESAlgo));
    aes->nRounds = nr;
    aes->roundKeys = (uint8_t**)malloc(4 * (nr + 1) * sizeof(uint8_t*));
    for (int i = 0; i < 4 * (nr + 1); i++) {
        aes->roundKeys[i] = (uint8_t*)malloc(4);
    }
    
    for (int i = 0; i < nk; i++) {
        aes->roundKeys[i][0] = key[i*4];
        aes->roundKeys[i][1] = key[i*4+1];
        aes->roundKeys[i][2] = key[i*4+2];
        aes->roundKeys[i][3] = key[i*4+3];
    }
    
    for (int i = nk; i < 4 * (nr + 1); i++) {
        uint8_t temp[4];
        memcpy(temp, aes->roundKeys[i-1], 4);
        
        if (i % nk == 0) {
            rotWord(temp);
            subWord(temp);
            temp[0] ^= rcon[i/nk - 1];
        } else if (nk > 6 && i % nk == 4) {
            subWord(temp);
        }
        
        memcpy(aes->roundKeys[i], aes->roundKeys[i-nk], 4);
        xorBytes(aes->roundKeys[i], temp);
    }
    return aes;
}

static void free_aes(AESAlgo* aes) {
    for (int i = 0; i < 4 * (aes->nRounds + 1); i++) {
        free(aes->roundKeys[i]);
    }
    free(aes->roundKeys);
    free(aes);
}

static void subBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state[i][j] = sBox[state[i][j]];
}

static void invSubBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state[i][j] = invSBox[state[i][j]];
}

static void shiftRows(uint8_t state[4][4]) {
    uint8_t temp;
    temp = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = temp;
    temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp; temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
    temp = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = temp;
}

static void invShiftRows(uint8_t state[4][4]) {
    uint8_t temp;
    temp = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = temp;
    temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp; temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
    temp = state[3][0]; state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = temp;
}

static uint8_t gfMul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return result;
}

static void mixColumns(uint8_t state[4][4]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[0][c], s1 = state[1][c], s2 = state[2][c], s3 = state[3][c];
        state[0][c] = gfMul(s0, 2) ^ gfMul(s1, 3) ^ s2 ^ s3;
        state[1][c] = s0 ^ gfMul(s1, 2) ^ gfMul(s2, 3) ^ s3;
        state[2][c] = s0 ^ s1 ^ gfMul(s2, 2) ^ gfMul(s3, 3);
        state[3][c] = gfMul(s0, 3) ^ s1 ^ s2 ^ gfMul(s3, 2);
    }
}

static void invMixColumns(uint8_t state[4][4]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[0][c], s1 = state[1][c], s2 = state[2][c], s3 = state[3][c];
        state[0][c] = gfMul(s0, 0x0e) ^ gfMul(s1, 0x0b) ^ gfMul(s2, 0x0d) ^ gfMul(s3, 0x09);
        state[1][c] = gfMul(s0, 0x09) ^ gfMul(s1, 0x0e) ^ gfMul(s2, 0x0b) ^ gfMul(s3, 0x0d);
        state[2][c] = gfMul(s0, 0x0d) ^ gfMul(s1, 0x09) ^ gfMul(s2, 0x0e) ^ gfMul(s3, 0x0b);
        state[3][c] = gfMul(s0, 0x0b) ^ gfMul(s1, 0x0d) ^ gfMul(s2, 0x09) ^ gfMul(s3, 0x0e);
    }
}

static void addRoundKey(uint8_t state[4][4], AESAlgo* a, int round) {
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] ^= a->roundKeys[round * 4 + c][r];
        }
    }
}

static void aes_encrypt_block(AESAlgo* a, const uint8_t* block, uint8_t* out) {
    uint8_t state[4][4];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state[i][j] = block[j*4+i];
            
    addRoundKey(state, a, 0);
    for (int round = 1; round < a->nRounds; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, a, round);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, a, a->nRounds);
    
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            out[j*4+i] = state[i][j];
}

static void aes_decrypt_block(AESAlgo* a, const uint8_t* block, uint8_t* out) {
    uint8_t state[4][4];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state[i][j] = block[j*4+i];
            
    addRoundKey(state, a, a->nRounds);
    for (int round = a->nRounds - 1; round >= 1; round--) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, a, round);
        invMixColumns(state);
    }
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, a, 0);
    
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            out[j*4+i] = state[i][j];
}

char* aes_encrypt(const char* plaintext, const char* key) {
    if (!plaintext || strlen(plaintext) == 0) return strdup("");
    AESAlgo* a = init_aes(key);
    if (!a) return NULL;
    
    size_t len = strlen(plaintext);
    int padding = 16 - (len % 16);
    size_t paddedLen = len + padding;
    uint8_t* padded = (uint8_t*)malloc(paddedLen);
    memcpy(padded, plaintext, len);
    for (int i = 0; i < padding; i++) padded[len + i] = padding;
    
    uint8_t* result = (uint8_t*)malloc(paddedLen);
    for (size_t i = 0; i < paddedLen; i += 16) {
        aes_encrypt_block(a, padded + i, result + i);
    }
    
    char* hex = hex_encode(result, paddedLen);
    free(padded);
    free(result);
    free_aes(a);
    return hex;
}

char* aes_decrypt(const char* ciphertext, const char* key) {
    if (!ciphertext || strlen(ciphertext) == 0) return strdup("");
    AESAlgo* a = init_aes(key);
    if (!a) return NULL;
    
    size_t decodedLen;
    uint8_t* decoded = hex_decode(ciphertext, &decodedLen);
    if (!decoded || decodedLen % 16 != 0) {
        if (decoded) free(decoded);
        free_aes(a);
        return NULL;
    }
    
    uint8_t* result = (uint8_t*)malloc(decodedLen);
    for (size_t i = 0; i < decodedLen; i += 16) {
        aes_decrypt_block(a, decoded + i, result + i);
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
        free_aes(a);
        return NULL;
    }
    
    decodedLen -= padding;
    char* output = (char*)malloc(decodedLen + 1);
    memcpy(output, result, decodedLen);
    output[decodedLen] = '\0';
    
    free(decoded);
    free(result);
    free_aes(a);
    return output;
}

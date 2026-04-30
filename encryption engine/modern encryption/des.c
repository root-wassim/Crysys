#include "des.h"
#include "../core/utils.h"
#include <string.h>
#include <stdlib.h>

static const int initialPermutation[] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

static const int finalPermutation[] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
};

static const int expansionTable[] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};

static const int pBox[] = {
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
};

static const int pc1[] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
};

static const int pc2[] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

static const int sBoxes[8][4][16] = {
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 9, 11, 6, 7, 2, 14, 0, 12, 5}
    },
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 14, 2}
    },
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 1, 9, 5, 0},
        {14, 12, 11, 4, 2, 1, 9, 10, 13, 7, 8, 15, 5, 6, 3, 0}
    },
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 11, 1, 13, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};

static void permute(const unsigned char* in, unsigned char* out, const int* table, int tableLen, int outIsBits) {
    if (outIsBits) {
        for (int i = 0; i < tableLen; i++) {
            int bitPos = table[i] - 1;
            out[i] = (in[bitPos / 8] >> (7 - (bitPos % 8))) & 1;
        }
    } else {
        memset(out, 0, (tableLen + 7) / 8);
        for (int i = 0; i < tableLen; i++) {
            int bitPos = table[i] - 1;
            int bit = (in[bitPos] & 1); // in is array of bits
            if (bit) out[i / 8] |= (1 << (7 - (i % 8)));
        }
    }
}

static void leftRotateBits(unsigned char* bits, int len, int n) {
    unsigned char temp[28];
    for (int i = 0; i < len; i++) {
        temp[i] = bits[(i + n) % len];
    }
    memcpy(bits, temp, len);
}

static void generateKeys(const char* key, unsigned char keys[16][48]) {
    unsigned char keyBits[64];
    for (int i = 0; i < 64; i++) {
        keyBits[i] = (key[i / 8] >> (7 - (i % 8))) & 1;
    }
    
    unsigned char permutedKey[56];
    permute(keyBits, permutedKey, pc1, 56, 1);
    
    unsigned char left[28], right[28];
    memcpy(left, permutedKey, 28);
    memcpy(right, permutedKey + 28, 28);
    
    int shifts[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
    for (int round = 0; round < 16; round++) {
        leftRotateBits(left, 28, shifts[round]);
        leftRotateBits(right, 28, shifts[round]);
        
        unsigned char combined[56];
        memcpy(combined, left, 28);
        memcpy(combined + 28, right, 28);
        
        permute(combined, keys[round], pc2, 48, 1);
    }
}

static void des_process_block(const unsigned char* block, unsigned char keys[16][48], int decrypt, unsigned char* result) {
    unsigned char blockBits[64];
    for (int i = 0; i < 64; i++) blockBits[i] = (block[i / 8] >> (7 - (i % 8))) & 1;
    
    unsigned char permuted[64];
    permute(blockBits, permuted, initialPermutation, 64, 1);
    
    unsigned char left[32], right[32];
    memcpy(left, permuted, 32);
    memcpy(right, permuted + 32, 32);
    
    for (int round = 0; round < 16; round++) {
        int keyIndex = decrypt ? 15 - round : round;
        
        unsigned char expanded[48];
        permute(right, expanded, expansionTable, 48, 1);
        
        unsigned char xored[48];
        for (int i = 0; i < 48; i++) xored[i] = expanded[i] ^ keys[keyIndex][i];
        
        unsigned char substituted[32];
        for (int i = 0; i < 8; i++) {
            int row = xored[i*6] * 2 + xored[i*6+5];
            int col = xored[i*6+1] * 8 + xored[i*6+2] * 4 + xored[i*6+3] * 2 + xored[i*6+4];
            int val = sBoxes[i][row][col];
            for (int j = 0; j < 4; j++) {
                substituted[i*4+j] = (val >> (3 - j)) & 1;
            }
        }
        
        unsigned char pBoxResult[32];
        permute(substituted, pBoxResult, pBox, 32, 1);
        
        unsigned char temp[32];
        memcpy(temp, right, 32);
        for (int i = 0; i < 32; i++) right[i] = left[i] ^ pBoxResult[i];
        memcpy(left, temp, 32);
    }
    
    unsigned char combined[64];
    memcpy(combined, right, 32);
    memcpy(combined + 32, left, 32);
    
    permute(combined, result, finalPermutation, 64, 0);
}

char* des_encrypt(const char* plaintext, const char* keyStr) {
    char key[8] = {0};
    strncpy(key, keyStr, 8);
    
    unsigned char keys[16][48];
    generateKeys(key, keys);
    
    size_t len = strlen(plaintext);
    int padding = 8 - (len % 8);
    size_t paddedLen = len + padding;
    unsigned char* padded = (unsigned char*)malloc(paddedLen);
    memcpy(padded, plaintext, len);
    for (int i = 0; i < padding; i++) padded[len + i] = padding;
    
    unsigned char* result = (unsigned char*)malloc(paddedLen);
    for (size_t i = 0; i < paddedLen; i += 8) {
        des_process_block(padded + i, keys, 0, result + i);
    }
    
    char* hex = hex_encode(result, paddedLen);
    free(padded);
    free(result);
    return hex;
}

char* des_decrypt(const char* ciphertext, const char* keyStr) {
    char key[8] = {0};
    strncpy(key, keyStr, 8);
    
    unsigned char keys[16][48];
    generateKeys(key, keys);
    
    size_t decodedLen;
    unsigned char* decoded = hex_decode(ciphertext, &decodedLen);
    if (!decoded || decodedLen % 8 != 0) {
        if (decoded) free(decoded);
        return NULL;
    }
    
    unsigned char* result = (unsigned char*)malloc(decodedLen);
    for (size_t i = 0; i < decodedLen; i += 8) {
        des_process_block(decoded + i, keys, 1, result + i);
    }
    
    int padding = result[decodedLen - 1];
    if (padding > 0 && padding <= 8) decodedLen -= padding;
    
    char* output = (char*)malloc(decodedLen + 1);
    memcpy(output, result, decodedLen);
    output[decodedLen] = '\0';
    
    free(decoded);
    free(result);
    return output;
}

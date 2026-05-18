#include "affine.h"
#include "../core/utils.h"
#include <string.h>

static int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

static int modInverse(int a, int m) {
    a = ((a % m) + m) % m;
    for (int i = 1; i < m; i++) {
        if ((a * i) % m == 1) {
            return i;
        }
    }
    return 1;
}

char* affine_encrypt(const char* plaintext, int a, int b) {
    if (gcd(a, 26) != 1) {
        a = 1; // Default
    }
    
    size_t len = strlen(plaintext);
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;

    for (size_t i = 0; i < len; i++) {
        char r = plaintext[i];
        if (r >= 'A' && r <= 'Z') {
            int num = r - 'A';
            int newNum = (a * num + b) % 26;
            if (newNum < 0) newNum += 26;
            result[i] = ReverseAlphabetMap[newNum];
        } else if (r >= 'a' && r <= 'z') {
            int num = r - 'a';
            int newNum = (a * num + b) % 26;
            if (newNum < 0) newNum += 26;
            result[i] = ReverseAlphabetMap[newNum] - 'A' + 'a';
        } else {
            result[i] = r;
        }
    }
    result[len] = '\0';
    return result;
}

char* affine_decrypt(const char* ciphertext, int a, int b) {
    if (gcd(a, 26) != 1) {
        a = 1; // Default
    }
    
    size_t len = strlen(ciphertext);
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;

    int aInv = modInverse(a, 26);

    for (size_t i = 0; i < len; i++) {
        char r = ciphertext[i];
        if (r >= 'A' && r <= 'Z') {
            int num = r - 'A';
            int newNum = (aInv * (num - b + 26)) % 26;
            if (newNum < 0) newNum += 26;
            result[i] = ReverseAlphabetMap[newNum];
        } else if (r >= 'a' && r <= 'z') {
            int num = r - 'a';
            int newNum = (aInv * (num - b + 26)) % 26;
            if (newNum < 0) newNum += 26;
            result[i] = ReverseAlphabetMap[newNum] - 'A' + 'a';
        } else {
            result[i] = r;
        }
    }
    result[len] = '\0';
    return result;
}

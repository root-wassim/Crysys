#include "elgamal.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t modExp(uint64_t base, uint64_t exp, uint64_t mod) {
    if (mod == 0) return 0;
    uint64_t result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

static uint64_t modInverse(uint64_t a, uint64_t m) {
    int64_t m0 = m, t, q;
    int64_t x0 = 0, x1 = 1;
    if (m == 1) return 0;
    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m, a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0) x1 += m0;
    return x1;
}

void elgamal_generate_keys(uint64_t p, uint64_t g, uint64_t* privKey, uint64_t* pubKey) {
    if (p <= 2) {
        *privKey = 0;
        *pubKey = 0;
        return;
    }
    srand(time(NULL));
    *privKey = (rand() % (p - 2)) + 2;
    *pubKey = modExp(g, *privKey, p);
}

void elgamal_encrypt(const char* plaintext, uint64_t p, uint64_t g, uint64_t pubKey, uint64_t** c1, uint64_t** c2, int* out_len) {
    size_t len = strlen(plaintext);
    *c1 = (uint64_t*)malloc(len * sizeof(uint64_t));
    *c2 = (uint64_t*)malloc(len * sizeof(uint64_t));
    
    srand(time(NULL));
    uint64_t k = (rand() % (p - 2)) + 2;
    
    for (size_t i = 0; i < len; i++) {
        (*c1)[i] = modExp(g, k, p);
        uint64_t s = modExp(pubKey, k, p);
        (*c2)[i] = (plaintext[i] * s) % p;
    }
    *out_len = len;
}

char* elgamal_decrypt(const uint64_t* c1, const uint64_t* c2, int len, uint64_t p, uint64_t privKey) {
    char* plaintext = (char*)malloc(len + 1);
    for (int i = 0; i < len; i++) {
        uint64_t s = modExp(c1[i], privKey, p);
        uint64_t sInv = modInverse(s, p);
        plaintext[i] = (char)((c2[i] * sInv) % p);
    }
    plaintext[len] = '\0';
    return plaintext;
}

#include "rsa.h"
#include <stdlib.h>
#include <string.h>

static uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

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

void rsa_generate_keys(uint64_t p, uint64_t q, uint64_t* n, uint64_t* e, uint64_t* d) {
    *n = p * q;
    uint64_t phi = (p - 1) * (q - 1);
    *e = 65537;
    if (gcd(*e, phi) != 1) {
        *e = 3;
        while (gcd(*e, phi) != 1) (*e) += 2;
    }
    *d = modInverse(*e, phi);
}

uint64_t* rsa_encrypt(const char* plaintext, uint64_t e, uint64_t n, int* out_len) {
    size_t len = strlen(plaintext);
    uint64_t* ciphertext = (uint64_t*)malloc(len * sizeof(uint64_t));
    for (size_t i = 0; i < len; i++) {
        ciphertext[i] = modExp(plaintext[i], e, n);
    }
    *out_len = len;
    return ciphertext;
}

char* rsa_decrypt(const uint64_t* ciphertext, int len, uint64_t d, uint64_t n) {
    char* plaintext = (char*)malloc(len + 1);
    for (int i = 0; i < len; i++) {
        plaintext[i] = (char)modExp(ciphertext[i], d, n);
    }
    plaintext[len] = '\0';
    return plaintext;
}

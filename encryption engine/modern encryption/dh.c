#include "dh.h"
#include <stdlib.h>
#include <time.h>

static uint64_t modExp(uint64_t base, uint64_t exp, uint64_t mod) {
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

void dh_generate_keys(uint64_t p, uint64_t g, uint64_t* privKey, uint64_t* pubKey) {
    srand(time(NULL));
    *privKey = (rand() % (p - 2)) + 2;
    *pubKey = modExp(g, *privKey, p);
}

uint64_t dh_compute_secret(uint64_t p, uint64_t privKey, uint64_t otherPubKey) {
    return modExp(otherPubKey, privKey, p);
}

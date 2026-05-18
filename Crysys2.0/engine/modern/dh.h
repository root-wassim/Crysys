#ifndef DH_H
#define DH_H

#include <stdint.h>

void dh_generate_keys(uint64_t p, uint64_t g, uint64_t* privKey, uint64_t* pubKey);
uint64_t dh_compute_secret(uint64_t p, uint64_t privKey, uint64_t otherPubKey);

#endif

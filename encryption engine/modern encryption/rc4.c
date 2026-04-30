#include "rc4.h"
#include "../core/utils.h"
#include <string.h>
#include <stdlib.h>

typedef struct {
    unsigned char state[256];
} RC4Algo;

static void init_rc4(RC4Algo* r, const char* key) {
    size_t keyLen = strlen(key);
    for (int i = 0; i < 256; i++) {
        r->state[i] = i;
    }
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + r->state[i] + key[i % keyLen]) % 256;
        unsigned char temp = r->state[i];
        r->state[i] = r->state[j];
        r->state[j] = temp;
    }
}

static unsigned char* process_rc4(RC4Algo* r, const unsigned char* data, size_t len) {
    unsigned char* output = (unsigned char*)malloc(len);
    int i = 0, j = 0;
    for (size_t n = 0; n < len; n++) {
        i = (i + 1) % 256;
        j = (j + r->state[i]) % 256;
        unsigned char temp = r->state[i];
        r->state[i] = r->state[j];
        r->state[j] = temp;
        unsigned char k = r->state[(r->state[i] + r->state[j]) % 256];
        output[n] = data[n] ^ k;
    }
    return output;
}

char* rc4_encrypt(const char* plaintext, const char* key) {
    RC4Algo r;
    init_rc4(&r, key);
    size_t len = strlen(plaintext);
    unsigned char* encrypted = process_rc4(&r, (const unsigned char*)plaintext, len);
    char* hex = hex_encode(encrypted, len);
    free(encrypted);
    return hex;
}

char* rc4_decrypt(const char* ciphertext, const char* key) {
    size_t decoded_len;
    unsigned char* decoded = hex_decode(ciphertext, &decoded_len);
    if (!decoded) return NULL;
    
    RC4Algo r;
    init_rc4(&r, key);
    unsigned char* decrypted = process_rc4(&r, decoded, decoded_len);
    
    char* result = (char*)malloc(decoded_len + 1);
    memcpy(result, decrypted, decoded_len);
    result[decoded_len] = '\0';
    
    free(decoded);
    free(decrypted);
    return result;
}

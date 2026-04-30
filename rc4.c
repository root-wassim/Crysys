#include "rc4.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void ksa(unsigned char *S, const unsigned char *key, size_t klen) {
    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xFF;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
}

static void prga(unsigned char *S, const unsigned char *in, unsigned char *out, size_t len) {
    int i = 0, j = 0;
    for (size_t n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        out[n] = in[n] ^ S[(S[i] + S[j]) & 0xFF];
    }
}

static unsigned char *rc4_process(const unsigned char *data, size_t len, const unsigned char *key, size_t klen, size_t *outlen) {
    if (!data || !key || klen == 0) return NULL;
    unsigned char S[256];
    ksa(S, key, klen);
    unsigned char *out = (unsigned char *)malloc(len);
    if (!out) return NULL;
    prga(S, data, out, len);
    if (outlen) *outlen = len;
    return out;
}

unsigned char *rc4_encrypt(const unsigned char *plaintext, size_t len, const unsigned char *key, size_t klen, size_t *outlen) {
    return rc4_process(plaintext, len, key, klen, outlen);
}

unsigned char *rc4_decrypt(const unsigned char *ciphertext, size_t len, const unsigned char *key, size_t klen, size_t *outlen) {
    return rc4_process(ciphertext, len, key, klen, outlen);
}

static int rc4_process_file(const char *infile, const char *outfile, const unsigned char *key, size_t klen) {
    FILE *fin = fopen(infile, "rb");
    if (!fin) return -1;
    fseek(fin, 0, SEEK_END);
    long sz = ftell(fin);
    rewind(fin);
    unsigned char *buf = (unsigned char *)malloc(sz);
    if (!buf) { fclose(fin); return -1; }
    fread(buf, 1, sz, fin);
    fclose(fin);
    size_t outlen;
    unsigned char *out = rc4_process(buf, sz, key, klen, &outlen);
    free(buf);
    if (!out) return -1;
    FILE *fout = fopen(outfile, "wb");
    if (!fout) { free(out); return -1; }
    fwrite(out, 1, outlen, fout);
    free(out);
    fclose(fout);
    return 0;
}

int rc4_encrypt_file(const char *infile, const char *outfile, const unsigned char *key, size_t klen) {
    return rc4_process_file(infile, outfile, key, klen);
}

int rc4_decrypt_file(const char *infile, const char *outfile, const unsigned char *key, size_t klen) {
    return rc4_process_file(infile, outfile, key, klen);
}

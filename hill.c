#include "hill.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static int mod26(int x) { return ((x % 26) + 26) % 26; }

static int det2x2(const int *m) {
    return mod26(m[0] * m[3] - m[1] * m[2]);
}

static int mod_inv(int a, int m) {
    a = ((a % m) + m) % m;
    for (int i = 1; i < m; i++)
        if ((a * i) % m == 1) return i;
    return -1;
}

static int invert_2x2(const int *m, int *inv) {
    int d = det2x2(m);
    int d_inv = mod_inv(d, 26);
    if (d_inv == -1) return -1;
    inv[0] = mod26(d_inv * m[3]);
    inv[1] = mod26(-d_inv * m[1]);
    inv[2] = mod26(-d_inv * m[2]);
    inv[3] = mod26(d_inv * m[0]);
    return 0;
}

static int det3x3(const int *m) {
    int v = m[0]*(m[4]*m[8] - m[5]*m[7])
          - m[1]*(m[3]*m[8] - m[5]*m[6])
          + m[2]*(m[3]*m[7] - m[4]*m[6]);
    return mod26(v);
}

static int invert_3x3(const int *m, int *inv) {
    int d = det3x3(m);
    int d_inv = mod_inv(d, 26);
    if (d_inv == -1) return -1;
    int cofactors[9];
    cofactors[0] = m[4]*m[8] - m[5]*m[7];
    cofactors[1] = -(m[3]*m[8] - m[5]*m[6]);
    cofactors[2] = m[3]*m[7] - m[4]*m[6];
    cofactors[3] = -(m[1]*m[8] - m[2]*m[7]);
    cofactors[4] = m[0]*m[8] - m[2]*m[6];
    cofactors[5] = -(m[0]*m[7] - m[1]*m[6]);
    cofactors[6] = m[1]*m[5] - m[2]*m[4];
    cofactors[7] = -(m[0]*m[5] - m[2]*m[3]);
    cofactors[8] = m[0]*m[4] - m[1]*m[3];
    for (int r = 0; r < 3; r++)
        for (int c = 0; c < 3; c++)
            inv[r*3+c] = mod26(d_inv * cofactors[c*3+r]);
    return 0;
}

static char *hill_process(const char *text, const int *key, int size, int decrypt) {
    if (!text || !key || (size != 2 && size != 3)) return NULL;
    size_t len = strlen(text);
    char *clean = (char *)malloc(len + 1);
    if (!clean) return NULL;
    size_t ci = 0;
    for (size_t i = 0; i < len; i++)
        if (isalpha((unsigned char)text[i]))
            clean[ci++] = toupper((unsigned char)text[i]);
    clean[ci] = '\0';
    while (ci % size != 0) clean[ci++] = 'X';
    clean[ci] = '\0';
    int inv_key[9];
    const int *use_key = key;
    if (decrypt) {
        if (size == 2) { if (invert_2x2(key, inv_key) != 0) { free(clean); return NULL; } }
        else           { if (invert_3x3(key, inv_key) != 0) { free(clean); return NULL; } }
        use_key = inv_key;
    }
    char *out = (char *)malloc(ci + 1);
    if (!out) { free(clean); return NULL; }
    for (size_t i = 0; i < ci; i += size) {
        for (int r = 0; r < size; r++) {
            int val = 0;
            for (int c = 0; c < size; c++)
                val += use_key[r * size + c] * (clean[i + c] - 'A');
            out[i + r] = (char)(mod26(val) + 'A');
        }
    }
    out[ci] = '\0';
    free(clean);
    return out;
}

char *hill_encrypt(const char *plaintext, const int *key_matrix, int size) {
    return hill_process(plaintext, key_matrix, size, 0);
}

char *hill_decrypt(const char *ciphertext, const int *key_matrix, int size) {
    return hill_process(ciphertext, key_matrix, size, 1);
}

static char *read_file_text(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, sz, f);
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

int hill_encrypt_file(const char *infile, const char *outfile, const int *key_matrix, int size) {
    char *text = read_file_text(infile);
    if (!text) return -1;
    char *result = hill_encrypt(text, key_matrix, size);
    free(text);
    if (!result) return -1;
    FILE *fout = fopen(outfile, "wb");
    if (!fout) { free(result); return -1; }
    fputs(result, fout);
    free(result);
    fclose(fout);
    return 0;
}

int hill_decrypt_file(const char *infile, const char *outfile, const int *key_matrix, int size) {
    char *text = read_file_text(infile);
    if (!text) return -1;
    char *result = hill_decrypt(text, key_matrix, size);
    free(text);
    if (!result) return -1;
    FILE *fout = fopen(outfile, "wb");
    if (!fout) { free(result); return -1; }
    fputs(result, fout);
    free(result);
    fclose(fout);
    return 0;
}

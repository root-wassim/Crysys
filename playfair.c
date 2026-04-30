#include "playfair.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static void build_matrix(const char *key, char matrix[5][5]) {
    int used[26] = {0};
    int pos = 0;
    used['J' - 'A'] = 1;
    for (size_t i = 0; key[i]; i++) {
        char c = toupper((unsigned char)key[i]);
        if (!isalpha((unsigned char)c)) continue;
        if (c == 'J') c = 'I';
        int idx = c - 'A';
        if (!used[idx]) {
            used[idx] = 1;
            matrix[pos / 5][pos % 5] = c;
            pos++;
        }
    }
    for (int i = 0; i < 26; i++) {
        if (!used[i]) {
            matrix[pos / 5][pos % 5] = (char)('A' + i);
            pos++;
        }
    }
}

static void find_pos(char matrix[5][5], char c, int *row, int *col) {
    if (c == 'J') c = 'I';
    for (int r = 0; r < 5; r++)
        for (int cl = 0; cl < 5; cl++)
            if (matrix[r][cl] == c) { *row = r; *col = cl; return; }
}

static char *prepare_text(const char *text) {
    size_t len = strlen(text);
    char *clean = (char *)malloc(len + 1);
    if (!clean) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (isalpha((unsigned char)text[i])) {
            char c = toupper((unsigned char)text[i]);
            if (c == 'J') c = 'I';
            clean[j++] = c;
        }
    }
    clean[j] = '\0';
    char *digrams = (char *)malloc(j * 2 + 2);
    if (!digrams) { free(clean); return NULL; }
    size_t di = 0, ci = 0;
    while (ci < j) {
        digrams[di++] = clean[ci];
        if (ci + 1 >= j) {
            digrams[di++] = 'X';
            ci++;
        } else if (clean[ci] == clean[ci + 1]) {
            digrams[di++] = 'X';
            ci++;
        } else {
            digrams[di++] = clean[ci + 1];
            ci += 2;
        }
    }
    digrams[di] = '\0';
    free(clean);
    return digrams;
}

static char *playfair_process(const char *text, const char *key, int encrypt) {
    if (!text || !key) return NULL;
    char matrix[5][5];
    build_matrix(key, matrix);
    char *prepared = prepare_text(text);
    if (!prepared) return NULL;
    size_t len = strlen(prepared);
    char *out = (char *)malloc(len + 1);
    if (!out) { free(prepared); return NULL; }
    int dir = encrypt ? 1 : -1;
    for (size_t i = 0; i < len; i += 2) {
        int r1, c1, r2, c2;
        find_pos(matrix, prepared[i], &r1, &c1);
        find_pos(matrix, prepared[i + 1], &r2, &c2);
        if (r1 == r2) {
            out[i]     = matrix[r1][(c1 + dir + 5) % 5];
            out[i + 1] = matrix[r2][(c2 + dir + 5) % 5];
        } else if (c1 == c2) {
            out[i]     = matrix[(r1 + dir + 5) % 5][c1];
            out[i + 1] = matrix[(r2 + dir + 5) % 5][c2];
        } else {
            out[i]     = matrix[r1][c2];
            out[i + 1] = matrix[r2][c1];
        }
    }
    out[len] = '\0';
    free(prepared);
    return out;
}

char *playfair_encrypt(const char *plaintext, const char *key) {
    return playfair_process(plaintext, key, 1);
}

char *playfair_decrypt(const char *ciphertext, const char *key) {
    return playfair_process(ciphertext, key, 0);
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

int playfair_encrypt_file(const char *infile, const char *outfile, const char *key) {
    char *text = read_file_text(infile);
    if (!text) return -1;
    char *result = playfair_encrypt(text, key);
    free(text);
    if (!result) return -1;
    FILE *fout = fopen(outfile, "wb");
    if (!fout) { free(result); return -1; }
    fputs(result, fout);
    free(result);
    fclose(fout);
    return 0;
}

int playfair_decrypt_file(const char *infile, const char *outfile, const char *key) {
    char *text = read_file_text(infile);
    if (!text) return -1;
    char *result = playfair_decrypt(text, key);
    free(text);
    if (!result) return -1;
    FILE *fout = fopen(outfile, "wb");
    if (!fout) { free(result); return -1; }
    fputs(result, fout);
    free(result);
    fclose(fout);
    return 0;
}

#include "playfair.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

typedef struct {
    char matrix[5][5];
} PlayfairAlgo;

static void init_playfair(PlayfairAlgo* p, const char* key) {
    int used[256] = {0};
    int idx = 0;
    
    size_t keyLen = strlen(key);
    for (size_t i = 0; i < keyLen; i++) {
        char c = toupper(key[i]);
        if (c == 'J') c = 'I';
        if (c >= 'A' && c <= 'Z' && !used[(unsigned char)c]) {
            p->matrix[idx / 5][idx % 5] = c;
            used[(unsigned char)c] = 1;
            idx++;
        }
    }
    
    for (char c = 'A'; c <= 'Z' && idx < 25; c++) {
        if (c != 'J' && !used[(unsigned char)c]) {
            p->matrix[idx / 5][idx % 5] = c;
            used[(unsigned char)c] = 1;
            idx++;
        }
    }
}

static void find_pos(PlayfairAlgo* p, char c, int* row, int* col) {
    if (c == 'J') c = 'I';
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            if (p->matrix[i][j] == c) {
                *row = i;
                *col = j;
                return;
            }
        }
    }
    *row = -1;
    *col = -1;
}

static char* prepare_text(const char* text, size_t* out_len) {
    size_t len = strlen(text);
    char* temp = (char*)malloc(len * 2 + 1);
    int t_idx = 0;
    
    for (size_t i = 0; i < len; i++) {
        char c = toupper(text[i]);
        if (c == 'J') c = 'I';
        if (c >= 'A' && c <= 'Z') {
            temp[t_idx++] = c;
        }
    }
    
    char* prepared = (char*)malloc(t_idx * 2 + 2);
    int p_idx = 0;
    
    for (int i = 0; i < t_idx; i++) {
        prepared[p_idx++] = temp[i];
        if (i + 1 < t_idx && temp[i] == temp[i+1]) {
            prepared[p_idx++] = 'X';
        }
    }
    if (p_idx % 2 == 1) {
        prepared[p_idx++] = 'X';
    }
    prepared[p_idx] = '\0';
    
    free(temp);
    *out_len = p_idx;
    return prepared;
}

char* playfair_encrypt(const char* plaintext, const char* key) {
    if (!key || strlen(key) == 0) return NULL;
    if (!plaintext || strlen(plaintext) == 0) return strdup("");
    PlayfairAlgo p;
    init_playfair(&p, key);
    
    size_t len;
    char* prepared = prepare_text(plaintext, &len);
    char* result = (char*)malloc(len + 1);
    
    for (size_t i = 0; i < len; i += 2) {
        int r1, c1, r2, c2;
        find_pos(&p, prepared[i], &r1, &c1);
        find_pos(&p, prepared[i+1], &r2, &c2);
        
        if (r1 == r2) {
            result[i] = p.matrix[r1][(c1 + 1) % 5];
            result[i+1] = p.matrix[r2][(c2 + 1) % 5];
        } else if (c1 == c2) {
            result[i] = p.matrix[(r1 + 1) % 5][c1];
            result[i+1] = p.matrix[(r2 + 1) % 5][c2];
        } else {
            result[i] = p.matrix[r1][c2];
            result[i+1] = p.matrix[r2][c1];
        }
    }
    result[len] = '\0';
    free(prepared);
    return result;
}

char* playfair_decrypt(const char* ciphertext, const char* key) {
    if (!key || strlen(key) == 0) return NULL;
    if (!ciphertext || strlen(ciphertext) == 0) return strdup("");
    size_t len = strlen(ciphertext);
    if (len % 2 != 0) return NULL;
    
    PlayfairAlgo p;
    init_playfair(&p, key);
    
    char* result = (char*)malloc(len + 1);
    for (size_t i = 0; i < len; i += 2) {
        int r1, c1, r2, c2;
        find_pos(&p, toupper(ciphertext[i]), &r1, &c1);
        find_pos(&p, toupper(ciphertext[i+1]), &r2, &c2);
        
        if (r1 == -1 || r2 == -1) {
            free(result);
            return NULL;
        }
        
        if (r1 == r2) {
            result[i] = p.matrix[r1][(c1 + 4) % 5];
            result[i+1] = p.matrix[r2][(c2 + 4) % 5];
        } else if (c1 == c2) {
            result[i] = p.matrix[(r1 + 4) % 5][c1];
            result[i+1] = p.matrix[(r2 + 4) % 5][c2];
        } else {
            result[i] = p.matrix[r1][c2];
            result[i+1] = p.matrix[r2][c1];
        }
    }
    
    char* final_res = (char*)malloc(len + 1);
    int f_idx = 0;
    final_res[f_idx++] = result[0];
    for (size_t i = 1; i < len - 1; i++) {
        if (result[i] == 'X' && result[i-1] == result[i+1] && (i % 2 == 1)) {
            // skip inserted X
        } else {
            final_res[f_idx++] = result[i];
        }
    }
    if (len > 1 && result[len-1] != 'X') {
        final_res[f_idx++] = result[len-1];
    } else if (len > 1 && result[len-1] == 'X' && (len % 2 == 0)) {
        // usually 'X' at end is padding, we skip it
    }
    final_res[f_idx] = '\0';
    free(result);
    return final_res;
}

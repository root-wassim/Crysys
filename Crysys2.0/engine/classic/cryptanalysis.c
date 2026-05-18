#include "cryptanalysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

double calc_index_of_coincidence(const char* text) {
    int counts[26] = {0};
    int total = 0;
    
    for (int i = 0; text[i]; i++) {
        if (isalpha(text[i])) {
            counts[toupper(text[i]) - 'A']++;
            total++;
        }
    }
    
    if (total <= 1) return 0.0;
    
    double ic = 0;
    for (int i = 0; i < 26; i++) {
        ic += (double)(counts[i] * (counts[i] - 1));
    }
    ic /= (double)(total * (total - 1));
    
    return ic;
}

char* probable_word_vigenere(const char* ciphertext, const char* probable_word) {
    size_t ct_len = strlen(ciphertext);
    size_t pw_len = strlen(probable_word);
    
    char clean_ct[4096] = {0};
    int j = 0;
    for(size_t i = 0; i < ct_len; i++){
        if(isalpha(ciphertext[i])){
            clean_ct[j++] = toupper(ciphertext[i]);
        }
    }
    ct_len = j;
    
    char clean_pw[256] = {0};
    j = 0;
    for(size_t i = 0; i < pw_len; i++){
        if(isalpha(probable_word[i])){
            clean_pw[j++] = toupper(probable_word[i]);
        }
    }
    pw_len = j;

    if (ct_len < pw_len || pw_len == 0) {
        return strdup("Error: Probable word is longer than ciphertext or empty.");
    }
    
    char* result = (char*)malloc(ct_len * pw_len * 5 + 1024);
    result[0] = '\0';
    
    strcat(result, "Sliding Probable Word Results (looking for repeating key patterns):\n");

    for (size_t offset = 0; offset <= ct_len - pw_len; offset++) {
        char key_fragment[256] = {0};
        for (size_t i = 0; i < pw_len; i++) {
            int diff = clean_ct[offset + i] - clean_pw[i];
            if (diff < 0) diff += 26;
            key_fragment[i] = diff + 'A';
        }
        char temp[512];
        sprintf(temp, "Offset %3zu: %s\n", offset, key_fragment);
        strcat(result, temp);
    }
    
    return result;
}

char* freq_analysis_vigenere(const char* ciphertext, int key_length) {
    if (key_length <= 0) return strdup("Invalid key length.");
    
    char clean_ct[4096] = {0};
    int j = 0;
    for(int i = 0; ciphertext[i]; i++){
        if(isalpha(ciphertext[i])){
            clean_ct[j++] = toupper(ciphertext[i]);
        }
    }
    int len = j;
    
    char* key = (char*)malloc(key_length + 1);
    for (int k = 0; k < key_length; k++) {
        int counts[26] = {0};
        for (int i = k; i < len; i += key_length) {
            counts[clean_ct[i] - 'A']++;
        }
        int max_count = -1;
        int max_char = 0;
        for (int c = 0; c < 26; c++) {
            if (counts[c] > max_count) {
                max_count = counts[c];
                max_char = c;
            }
        }
        // Assume max_char corresponds to 'E' (index 4)
        int diff = max_char - ('E' - 'A');
        if (diff < 0) diff += 26;
        key[k] = diff + 'A';
    }
    key[key_length] = '\0';
    return key;
}

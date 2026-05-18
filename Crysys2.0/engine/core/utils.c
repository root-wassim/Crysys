#include "utils.h"

const char ReverseAlphabetMap[26] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z'
};

int get_alphabet_index(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    return -1;
}

char* read_file(const char* filename, size_t* length) {
    FILE* f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* string = (char*)malloc(fsize + 1);
    if (!string) { fclose(f); return NULL; }
    
    size_t read_size = fread(string, 1, fsize, f);
    if (read_size != (size_t)fsize) {
        free(string);
        fclose(f);
        return NULL;
    }
    string[fsize] = 0;
    
    if (length) *length = fsize;
    fclose(f);
    return string;
}

int write_file(const char* filename, const char* data, size_t length) {
    FILE* f = fopen(filename, "wb");
    if (!f) return 0;
    size_t written = fwrite(data, 1, length, f);
    fclose(f);
    return written == length;
}

char* hex_encode(const unsigned char* data, size_t len) {
    char* hex = (char*)malloc(len * 2 + 1);
    if (!hex) return NULL;
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", data[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

static unsigned char hex_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

unsigned char* hex_decode(const char* hex_str, size_t* out_len) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) return NULL;
    size_t result_len = len / 2;
    unsigned char* data = (unsigned char*)malloc(result_len);
    if (!data) return NULL;
    
    for (size_t i = 0; i < result_len; i++) {
        data[i] = (hex_to_val(hex_str[i * 2]) << 4) | hex_to_val(hex_str[i * 2 + 1]);
    }
    if (out_len) *out_len = result_len;
    return data;
}

#ifndef CORE_UTILS_H
#define CORE_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

extern const char ReverseAlphabetMap[26];

int get_alphabet_index(char c);
char* read_file(const char* filename, size_t* length);
int write_file(const char* filename, const char* data, size_t length);
char* hex_encode(const unsigned char* data, size_t len);
unsigned char* hex_decode(const char* hex_str, size_t* out_len);

#endif

#ifndef CRYPTANALYSIS_H
#define CRYPTANALYSIS_H

// Calculates Index of Coincidence
double calc_index_of_coincidence(const char* text);

// Probable Word Method
// Returns a string containing all offsets and their respective keys
char* probable_word_vigenere(const char* ciphertext, const char* probable_word);

// Frequency analysis for Vigenere 
// Uses French frequency ('E' is assumed the most frequent)
char* freq_analysis_vigenere(const char* ciphertext, int key_length);

#endif

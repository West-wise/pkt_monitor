#ifndef BM_H
#define BM_H

#include "common.h"
#include "pattern.h"

#define ALPHABET_SIZE 256

typedef struct bmPattern{
        const unsigned char *pattern;
        size_t pattern_len;

        int bad_char_shift[ALPHABET_SIZE];

        int *suffixes;
        int *good_suffix_shift;
} bmPattern;

bmPattern *bm_process_pattern(const char *pattern_str);
void bm_destroy_pattern(bmPattern *bm_pattern);
int bm_search(const bmPattern *bm_pattern, const unsigned char *text, size_t text_len);

#endif
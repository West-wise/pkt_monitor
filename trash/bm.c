#include "bm.h"

static void calc_suffixes(const unsigned char *pattern, size_t pattern_len, int *suffixes){
        int f = 0, g = 0;
        suffixes[pattern_len - 1] = pattern_len; 
        for (int i = pattern_len - 2; i >= 0; --i) {
                if (i > g && suffixes[i + pattern_len - 1 - f] < i - g) {
                            suffixes[i] = suffixes[i + pattern_len - 1 - f];
                } else {
                    if (i < g) {
                            g = i;
                    }
                    f = i;
                    while (g >= 0 && pattern[g] == pattern[g + pattern_len - 1 - f]) {
                        --g;
                   }
                   suffixes[i] = f - g;
                }
        }
}


static void calc_good_suffix_shift(const unsigned char *pattern, size_t pattern_len, int *suffixes, int *good_suffix_shift){
        for (size_t i = 0; i < pattern_len; i++) {
                good_suffix_shift[i] = pattern_len;
        }
        for (int i = pattern_len - 1; i >= 0; --i) {
            if (suffixes[i] == i + 1) { 
                for (int j = 0; j < (int)pattern_len - 1 - i; ++j) {
                    if (good_suffix_shift[j] == (int)pattern_len) {
                            good_suffix_shift[j] = pattern_len - 1 - i;
                    }
                }
            }
        }
        for (int i = 0; i < (int)pattern_len - 1; ++i) {
                good_suffix_shift[pattern_len - 1 - suffixes[i]] = pattern_len - 1 - i;
        }
}




bmPattern *bm_process_pattern(const char *pattern_str){
        if(pattern_str==NULL){
                fprintf(stderr, "pattern string is null\n");
                return NULL;
        }
        bmPattern *bm_pattern = (bmPattern *)malloc(sizeof(bmPattern));
        if(bm_pattern == NULL){
                fprintf(stderr, "Failed to malloc bmPattern\n");
                return NULL;
        }

        bm_pattern->pattern = (const unsigned char *)pattern_str;
        bm_pattern->pattern_len = strlen(pattern_str);

        if(bm_pattern->pattern_len == 0){
                fprintf(stderr, "empty pattern\n");
                free(bm_pattern);
                return NULL;
        }

        for(int i = 0; i < ALPHABET_SIZE; i++){
                bm_pattern->bad_char_shift[i] = bm_pattern->pattern_len;
        }

        for(size_t i =0; i<bm_pattern->pattern_len - 1; i++){
                bm_pattern->bad_char_shift[bm_pattern->pattern[i]] = bm_pattern->pattern_len-1-i;
        }

        bm_pattern->suffixes = (int*)malloc(sizeof(int) * bm_pattern->pattern_len);
        bm_pattern->good_suffix_shift = (int*)malloc(sizeof(int)*bm_pattern->pattern_len);
        if(bm_pattern->suffixes == NULL || bm_pattern->good_suffix_shift == NULL){
                fprintf(stderr, "Failed to malloc suffix\n");
                if(bm_pattern->suffixes)free(bm_pattern->suffixes);
                if(bm_pattern->good_suffix_shift) free(bm_pattern->good_suffix_shift);
                free(bm_pattern);
                return NULL;
        }


        calc_suffixes(bm_pattern->pattern, bm_pattern->pattern_len, bm_pattern->suffixes);
        calc_good_suffix_shift(bm_pattern->pattern, bm_pattern->pattern_len, bm_pattern->suffixes, bm_pattern->good_suffix_shift);

        return bm_pattern;
}


void bm_destroy_pattern(bmPattern *bm_pattern){
        if(bm_pattern == NULL) return;
        if(bm_pattern->suffixes) free(bm_pattern->suffixes);
        if(bm_pattern->good_suffix_shift) free(bm_pattern->good_suffix_shift);
        free(bm_pattern);
}



int bm_search(const bmPattern *bm_pattern, const unsigned char *text, size_t text_len) {
        if (bm_pattern == NULL || bm_pattern->pattern == NULL || bm_pattern->pattern_len == 0) return -1;
        if (text == NULL || text_len == 0) return -1;
        if (text_len < bm_pattern->pattern_len) return -1; 
        long long i = 0; 
        long long j;     
        while (i <= (long long)text_len - (long long)bm_pattern->pattern_len) {
            j = bm_pattern->pattern_len - 1; 
            while (j >= 0 && bm_pattern->pattern[j] == text[i + j]) {
                j--; 
            }
            if (j < 0) {
                    return (int)i; 
            } else {
                    int bad_char_shift = bm_pattern->bad_char_shift[text[i + j]] - ((int)bm_pattern->pattern_len - 1 - j);
                    if (bad_char_shift < 1) bad_char_shift = 1; 
    
                    int good_suffix_shift = bm_pattern->good_suffix_shift[j];
                    i += (bad_char_shift > good_suffix_shift) ? bad_char_shift : good_suffix_shift;                                                                                                    }
           }

        return 0; 
}

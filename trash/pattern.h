#ifndef PATTERN_H
#define PATTERN_H

#include "common.h"
#include <stddef.h>

#define SIZE 256
#define PATTERN_CAPACITY 10



typedef struct PatternRule{
        char *value_str;
} PatternRule;


typedef struct PatternList{
        PatternRule rules[PATTERN_CAPACITY];
        size_t count;
} PatternList;

void free_pattern(PatternRule *rule);

void destroy_pattern_list(PatternList *list);

PatternList *load_patterns_from_file(const char *file_name);

int add_pattern_rule(PatternList *list, const PatternRule *new_rule);

#endif
#include "pattern.h"
#include "common.h"


void free_pattern(PatternRule *rule){
        if(rule==NULL) return;
        if(rule->value_str != NULL){
                free(rule->value_str);
                rule->value_str = NULL;
        }
}

void destroy_pattern_list(PatternList *list){
        if(list==NULL) return;

        for(size_t i = 0; i < list->count; i++){
                free_pattern(&list->rules[i]);
        }
        free(list);
}

int add_pattern_rule(PatternList *list, const PatternRule *new_rule){
    if(list == NULL || new_rule == NULL) {
        fprintf(stderr, "Invalid parameter\n");
        return -1;
    }
    if(list->count < PATTERN_CAPACITY){
        list->rules[list->count].value_str = strdup(new_rule->value_str);
        if (list->rules[list->count].value_str == NULL) {
            fprintf(stderr, "Failed to strdup for pattern rule value\n");
            return -1;
        }
        list->count++;
        return 0;
    }else{
        printf("Max Number of Pattern is %d\n", PATTERN_CAPACITY);
        return -1;
    }
}



PatternList *load_patterns_from_file(const char *file_name){
        printf("[DEBUG] : Open pattern file: %s\n", file_name);
        FILE *fp = fopen(file_name,"r");
        if(fp == NULL){
                fprintf(stderr, "Failed to open file\n");
                perror("[PERROR] : Failed to open file");
                return NULL;
        }

        PatternList *pattern_list = (PatternList*)malloc(sizeof(PatternList));
        if(pattern_list == NULL){
                fprintf(stderr, "Failed to malloc PatternList\n");
                fclose(fp);
                return NULL;
        }
        pattern_list->count = 0;

        char line_buffer[1024];
        unsigned int line_num = 0;
        while(fgets(line_buffer,sizeof(line_buffer), fp)!= NULL){
                line_num++;
                line_buffer[strcspn(line_buffer, "\n\r")] = '\0';

                if(strlen(line_buffer) == 0 || line_buffer[0] == '#'){
                        continue;
                }

                char *token_type = strtok(line_buffer, ":");
                char *token_value = strtok(NULL, "");

                PatternRule new_rule = {0};

                if(strcmp(token_type,"string")==0){
                        new_rule.value_str = strdup(token_value);
                        if(new_rule.value_str == NULL){
                                fprintf(stderr,"Failed to malloc pattern val\n");
                                fclose(fp);
                                return NULL;
                        }
                } else { 
                        fprintf(stderr, "your pattern file have to start \"string:\"\n");
                        continue;
                }
                if(add_pattern_rule(pattern_list, &new_rule)!=0){
                        fprintf(stderr, "Failed to add new pattern rule\n");
                        free_pattern(&new_rule);
                        destroy_pattern_list(pattern_list);
                        fclose(fp);
                        return NULL;
                } else{
                        printf("Adding Rule successfully\n");
                }

        }
        return pattern_list;
}
#include "trie.h"
#include <ctype.h>

#define LINE_LENGTH 1024

TrieNode* createNode(){
	TrieNode *node = (TrieNode *)malloc(sizeof(TrieNode));
	if(node == NULL){
		fprintf(stderr, "Failed to malloc TrieNode\n");
		return NULL;
	}
	node->isEnd = -1;
	for(int i=0; i<38; i++){
		node->trieNode[i] = NULL;
	}
	return node;
}

int char_to_idx(char c){
	if('0'<= c && c <= '9') return c - '0';
	if('a' <= c && c <='z') return c - 'a'+10;
	if(c == '.') return 37;
	if(c == '-') return 36;
	return -1;
}


void insert(TrieNode *root, const char *host){
	TrieNode *current = root;
	if(root == NULL || host == NULL){
		fprintf(stderr, "trie cannot insert null\n");
		return;
	}
	while(*host){
		int idx = char_to_idx(tolower(*host));
		if(idx < 0 || idx >= 38) {
			host++;
			continue;
		};
		if(current->trieNode[idx]==NULL){
			TrieNode *tmp_node = createNode();
			if(tmp_node == NULL){
				fprintf(stderr, "create trie node fail\n");
				return;
			}
			current->trieNode[idx] = tmp_node;
		}
		current = current->trieNode[idx];
		host++;
	}
	current->isEnd = 0;
}

int find(TrieNode *root, const char *host){
	if(root == NULL || host == NULL) return -1;
	TrieNode *current = root;
	while(*host){
		int idx = char_to_idx(tolower(*host));
		if(idx < 0 || idx >= 38) {
			host++;
			continue;
		}
		if(current->trieNode[idx] == NULL){
			return -1;
		}
		current = current->trieNode[idx];
		host++;
	}
	return current->isEnd;	
}

void freeTrie(TrieNode *node){
	if(node == NULL) return;
	for(int i = 0; i<38; i++){
		if(node->trieNode[i]!=NULL){
			freeTrie(node->trieNode[i]);
			node->trieNode[i] = NULL;
		}
	}
	free(node);
}

int triePreprocess(const char *file_name, TrieNode *trie){
	FILE *fp = fopen(file_name, "r");
	if(fp == NULL){
		fprintf(stderr, "Failed to file open\n");
		return -1;
	}
	char line_buffer[LINE_LENGTH];
	char *next_ptr;
	unsigned int line_num = 0;
	while(fgets(line_buffer, LINE_LENGTH, fp)){
		line_num++;
		line_buffer[strcspn(line_buffer, "\n\r")] = '\0';
		char *token = strtok_r(line_buffer, ",",&next_ptr);
		int token_cnt = 0;
		while(token != NULL){
			token_cnt++;
			if(token_cnt == 2){
				// printf("token : %s\n", token);
				insert(trie, token);				
			}
			token = strtok_r(NULL,",",&next_ptr);
		}
	}
	fclose(fp);
	return 0;
}

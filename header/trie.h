
#ifndef TRIE_H
#define TRIE_H

#define CHAR_LEN 38

#include "common.h"

typedef struct TrieNode{
	int isEnd;
	struct TrieNode *trieNode[38];
} TrieNode;

TrieNode* createNode();

void insert(TrieNode *root, const char *host);

int find(TrieNode *root, const char *host);

void freeTrie(TrieNode *node);

int triePreprocess(const char *file_name, TrieNode *node);

#endif

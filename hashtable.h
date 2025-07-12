#ifndef HTABLE_H
#define HTABLE_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#define HTABLE_VLA_CAP 10 
#define HTABLE_ERR -1
#define HTABLE_SUCC 0

struct table_entry_data {
	const char *domain_name;
	uint32_t  TTL;
	in_addr_t IPv4;
};

struct table_entry {
	struct table_entry_data data;
	struct table_entry *next;
};

typedef struct {
	size_t length;
	struct table_entry *entries[HTABLE_VLA_CAP];
} HashTable;

uint32_t table_hash(HashTable*, const char*);
void table_append(HashTable*, const char*, struct table_entry);
struct table_entry *table_lookup(HashTable*, const char*);
int table_remove(HashTable*, const char*);
void table_free(HashTable*);

#endif

#ifdef HTABLE_IMPLEMENTATION

#include <stdlib.h>
#include <string.h>

// key max size is 32 chars!
uint32_t table_hash(HashTable *ht, const char *key) {
	if (!key) return HTABLE_ERR;
	int result = 0;
	while (*key != '\0') result += *key++;
	return result;
}

void table_append(HashTable *ht, struct table_entry_data entry_data) {
	// TODO: FUCK ERROR CHECKING MALLOC NEVER FAILS IN 2025
	struct table_entry *hte = (struct table_entry*)malloc(sizeof entry_data);
	hte->next = NULL;
	hte->data = entry_data;

	int index = table_hash(ht, entry_data.domain_name);

	if (ht->entries[index] == NULL) { ht->entries[index] = hte; return; }
	
	struct table_entry *curr;
	for (curr =  ht->entries[index]; curr->next; curr = curr->next);
	curr->next = hte;
}

struct table_entry *table_lookup(HashTable *ht, const char *domain_name) {
	int index = table_hash(ht, domain_name);
	if (ht->entries[index] == NULL) return NULL;
	for (struct table_entry *te = ht->entries[index]; te; te = te->next)
		if (strcmp(te->data.domain_name, domain_name) == 0) return te;
	return NULL;
}

int table_remove(HashTable *ht, const char *domain_name) {
	int index = table_hash(ht, domain_name);
	if (ht->entries[index] == NULL) return HTABLE_ERR;
	
	// find it's index in the linked list
	// if the last free and NULL
	// if middle free and next to prev next
	// if first head is next
	struct table_entry *prev = NULL, *curr;
	// I know I know I'm fucking smart
	for (curr = ht->entries[index]; curr || prev; curr = (prev = curr)->next) {
		if (strcmp(curr->data.domain_name, domain_name) == 0) {
			if (prev == NULL) {
				ht->entries[index] = NULL;
			} else if (curr == NULL) {
				prev->next = NULL;
			} else {
				prev->next = curr->next;
			}
			
			free(curr);
			return HTABLE_SUCC;
		}
	}

	return HTABLE_ERR;
}

void table_free(HashTable *ht) {
	for (int i = 0; i < sizeof ht->entries; i++) {
		struct table_entry *ptr = ht->entries[i];
		while (ptr) {
			void *temp = ptr;
			ptr = ptr->next;
			free(ptr);
		}
		ht->entries[i] = null;
	}
}

#endif

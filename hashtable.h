#ifndef HTABLE_H
#define HTABLE_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

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
	size_t capacity;
	struct table_entry **entries;
} HashTable;

void table_append(HashTable*, struct table_entry_data);
struct table_entry *table_lookup(HashTable*, const char*);
int table_remove(HashTable*, const char*);
void table_free(HashTable*);

#endif

#ifdef HTABLE_IMPLEMENTATION

#include <string.h>
#include <stdlib.h>

uint32_t hash(HashTable *ht, const char* key) {
    	uint32_t sum = 0, factor = 31;
    	for (int i = 0; i < strlen(key); i++) {
    	    	sum += (key[i] * factor) % ht->capacity;
	    	sum %= ht->capacity;
    	    	factor *= 31;
		factor %= __INT16_MAX__;
    	}
    	return sum;
}

void table_append(HashTable *ht, struct table_entry_data entry_data) {
	// TODO: FUCK ERROR CHECKING MALLOC NEVER FAILS IN 2025
	struct table_entry *hte = (struct table_entry*)malloc(sizeof entry_data);
	hte->next = NULL;
	hte->data = entry_data;

	int index = hash(ht, entry_data.domain_name);

	if (ht->entries[index] == NULL) { ht->entries[index] = hte; return; }
	
	struct table_entry *curr;
	for (curr =  ht->entries[index]; curr->next; curr = curr->next);
	curr->next = hte;
}

struct table_entry *table_lookup(HashTable *ht, const char *domain_name) {
	int index = hash(ht, domain_name);
	if (ht->entries[index] == NULL) return NULL;
	for (struct table_entry *te = ht->entries[index]; te; te = te->next)
		if (strcmp(te->data.domain_name, domain_name) == 0) return te;
	return NULL;
}

int table_remove(HashTable *ht, const char *domain_name) {
	int index = hash(ht, domain_name);
	if (ht->entries[index] == NULL) return HTABLE_ERR;
	
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
	for (int i = 0; i < ht->capacity; i++) {
		struct table_entry *ptr = ht->entries[i];
		while (ptr) {
			void *temp = ptr;
			ptr = ptr->next;
			free(temp);
		}
		ht->entries[i] = NULL;
	}
}

#endif

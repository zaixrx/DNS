#ifndef STRB_H
#define STRB_H

#include <stddef.h>

#define STRB_FAILURE -1

typedef struct string_framgent {
	struct string_framgent *next;
	size_t length;
	char   *str;
} StringFragment;

typedef struct string_builder {
	struct string_framgent *head;
	struct string_framgent *tail;
	size_t length;
} StringBuilder;

StringBuilder *strb_create();

int  strb_empty   (StringBuilder *strb);
int  strb_append  (StringBuilder *strb, const char *str);
int  strb_concat  (StringBuilder *strb, char *str);
int  strb_reset   (StringBuilder *strb);
int  strb_free    (StringBuilder *strb);

#endif

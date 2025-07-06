#include <string.h>
#include <stdlib.h>
#include "sb.h"

StringBuilder *strb_create() {
	return calloc(sizeof(StringBuilder), 1);
}

int strb_empty(StringBuilder *strb) {
	return strb->head == NULL || strb->tail == NULL;
}

int strb_append(StringBuilder *strb, const char *str) {
	if (!str || *str == '\n') return 0;

	StringFragment *f = malloc(sizeof(StringFragment));

	if (!f) return STRB_FAILURE;

	f->length = strlen(str);
	f->str    = malloc(sizeof(char) * (f->length + 1));
	f->next   = NULL;
	strcpy(f->str, str);

	if (strb_empty(strb)) {
		strb->head = f;
	} else {
		strb->tail->next = f;
	}

	strb->tail = f;

	return f->length;
}

int strb_concat(StringBuilder *strb, char *str) {
	StringFragment *f = strb->head;
	int len = 0;

	while (f) {
		strcpy(str + len, f->str);
		len += f->length;
		f    = f->next;
	}

	return len;
}

int strb_reset(StringBuilder *strb) {
	if (!strb) return STRB_FAILURE;
	StringFragment *f = strb->head;
	while (f != strb->tail) {
		f = f->next;
		free(f->str);
		free(f);
	}
	strb->head = strb->tail = NULL;
	strb->length = 0;
	return 0;
}

int strb_free(StringBuilder *strb) {
	if (strb_reset(strb) == STRB_FAILURE) return STRB_FAILURE;
	free(strb);
	return 0;
}

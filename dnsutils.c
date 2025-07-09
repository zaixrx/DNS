#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cjson/cJSON.h>

#include "dnsutils.h"

/*
	Hello! Mr imaginary reader how is your day, I hope it's going well!
	thankfully I was not dumb enough(like previous times) and I'll give
	a short description on how I write my dumb code!

	general form of functions(don't care about the syntax fucker!)
	function manipulate_output(*input, *output);
	function write_data(*data);
	function read_data (data);

	a dns_packet describes the data represeted by the buffer in a structured
	manner

	when I implement an algorithm my philosphy is: if you give the algorithm a disrupted input, you'll only fuck yourself which is rather a trival thinking pattern!
*/

static inline uint8_t getb(struct dns_buffer *b) {
	return (uint8_t)b->buf[b->pos++];
}

static inline uint16_t gets(struct dns_buffer *b) {
	return 	((uint16_t)getb(b) << 0)|
		((uint16_t)getb(b) << 8);
}

static inline uint32_t getl(struct dns_buffer *b) {
	return 	((uint32_t)getb(b) << 0) |
		((uint32_t)getb(b) << 8) |
		((uint32_t)getb(b) << 16)|
		((uint32_t)getb(b) << 24);
}

static inline void getr(struct dns_buffer *b, void *d, uint8_t d_size) {
	if  (b->pos + d_size >= BUFF_SIZE) return;
	memcpy(d, b->buf, d_size);
	b->size += d_size;
}

static inline uint8_t seekb(struct dns_buffer *p) {
	return (uint8_t)p->buf[p->pos];
}

static inline void writeb(struct dns_buffer *b, uint8_t d) {
	if (b->size >= BUFF_SIZE) return;
	b->buf[b->size++] = d;
}

static inline void writes(struct dns_buffer *b, uint16_t d) {
	writeb(b, (uint8_t)(d >> 0  & 0xFF));
	writeb(b, (uint8_t)(d >> 8  & 0xFF));
}

static inline void writel(struct dns_buffer *b, uint32_t d) {
	writeb(b, (uint8_t)(d >> 0  & 0xFF));
	writeb(b, (uint8_t)(d >> 8  & 0xFF));
	writeb(b, (uint8_t)(d >> 16 & 0xFF));
	writeb(b, (uint8_t)(d >> 24 & 0xFF));
}

// write range
static inline void writer(struct dns_buffer *b, const char *d, size_t d_size) {
	if (b->size + d_size >= BUFF_SIZE) return;
	memcpy(b->buf + b->size, d, d_size);
	b->size += d_size;
}

uint32_t parse_labels(struct dns_buffer *b, StringBuilder *strb) {
	uint8_t  len  = getb(b), next_len = 0;
	uint16_t size = 1;

	char label[64];

	while (len > 0) {
		getr(b, label, len);
		next_len = getb(b);
		size += len + 1;

		if (next_len > 0) label[len++] = '.';
		label[len] = '\0';

		if (strb_append(strb, label) < 0) return -1;

		len = next_len;
	}

	return size;
}

int next_label(const char *domain, char *label, int *offset) {
	int    label_size = 0;

	const char *buf = domain + *offset;

	while (buf[label_size] != '.' && buf[label_size] != '\0') { label_size++; }
	if (label_size == 0) return EOF;

	memcpy(label, buf, label_size); label[label_size] = '\0';
	*offset += buf[label_size] == '\0' ? label_size : label_size + 1;

	return label_size;
}

int write_labels(struct dns_buffer *b, const char *domain) {
	if (domain == NULL || *domain == '\0') return 0;
	
	char label[64];
	int  lsize, size = 0, offset = 0;

	while ((lsize = next_label(domain, label, &offset)) != EOF) {
		writeb(b, lsize);
		writer(b, label, lsize);
		size += lsize+1;
	}

	writeb(b, '\0');
	return size+1;
}

int dns_parse_header(struct dns_buffer *b, struct dns_header *out) {
	if (!(out && b)) return -1;

	out->id = gets(b);

	uint16_t flags = gets(b);

	uint8_t  first = flags & 0xFF;
	uint8_t second = flags >> 8;

	out->rescode             = (ResultCode)(flags & 0xF);
        out->checking_disabled   = first & (1 << 4);
        out->authed_data         = first & (1 << 5);
	out->z        	         = first & (1 << 6);
	out->recursion_available = first & (1 << 7);

	out->recursion_desired    = second & (1 << 0);
	out->truncated_message    = second & (1 << 1);
	out->authoritative_answer = second & (1 << 2);
	out->opcode               = second & 0b01111000;
	out->response             = second & (1 << 7);

	out->questions = gets(b);
	out->answers   = gets(b);
	out->authoritative_entries = gets(b);
	out->resource_entries      = gets(b);

	return HEADER_SIZE;
}

// NOT_TESTED
int dns_write_header(struct dns_header h, struct dns_buffer *b) {
	writes(b, h.id);

	uint8_t first = 0, second = 0;
	first  |= h.rescode & 0xF;
	first  |= h.checking_disabled << 4;
	first  |= h.authed_data << 5;
	first  |= h.z << 6;
	first  |= h.recursion_available << 7;
	second |= h.recursion_desired    << 0;
	second |= h.truncated_message    << 1;
	second |= h.authoritative_answer << 2;
	second |= h.opcode               << 3;
	second |= h.response             << 7;
	writes(b, second << 8 | first);

	writes(b, h.questions);
	writes(b, h.answers);
	writes(b, h.authoritative_entries);
	writes(b, h.resource_entries);
	return 0;
}

void dns_print_header(struct dns_header h) {
	cJSON *json = cJSON_CreateObject();
	cJSON_AddNumberToObject(json, "id", h.id);

	cJSON *flags = cJSON_CreateObject();
	cJSON_AddBoolToObject  (flags, "recursion desired", h.recursion_desired);
	cJSON_AddBoolToObject  (flags, "truncated message", h.truncated_message);
	cJSON_AddBoolToObject  (flags, "authoritative answer", h.authoritative_answer);
	cJSON_AddNumberToObject(flags, "opcode", h.opcode);
	cJSON_AddBoolToObject  (flags, "response", h.response);
	cJSON_AddNumberToObject(flags, "rescode" , h.rescode);
	cJSON_AddBoolToObject  (flags, "checking disabled", h.checking_disabled);
	cJSON_AddBoolToObject  (flags, "authed data", h.authed_data);
	cJSON_AddBoolToObject  (flags, "z", h.z);
	cJSON_AddBoolToObject  (flags, "recursion available", h.recursion_available);

	cJSON_AddItemToObject(json, "flags", flags);

	cJSON_AddNumberToObject(json, "questions", h.questions);
	cJSON_AddNumberToObject(json, "answers"  , h.answers);
	cJSON_AddNumberToObject(json, "authoritative entries", h.authoritative_entries);
	cJSON_AddNumberToObject(json, "resource entries", h.resource_entries);

	printf("Header: %s\n", cJSON_Print(json));

	cJSON_Delete(json);
}

int dns_parse_questions(struct dns_buffer *p, struct dns_question **questions, int questions_count) {
	StringBuilder *strb = strb_create();

	while (questions_count-- > 0) {
		struct dns_question *question = malloc(sizeof(struct dns_question));
		questions[questions_count] = question;

		bool must_return = false;
		int  org_pos     = 0; // meant for referencing

		// the next byte is the index
		if (seekb(p) == 0xC0) {
			p->pos++;
			int target_index = getb(p);
			org_pos          = p->pos;
			p->pos      	 = target_index;
			must_return 	 = true;
		} 

		if (parse_labels(p, strb) < 0) return -1;
		p->pos = must_return ? org_pos : p->pos;

		if (strb_concat(strb, question->Name) < 0) return -1;
		if (strb_reset(strb) < 0) 		   return -1;

		question->Type   = gets(p);
		question->Class  = gets(p);
	}	

	return strb_free(strb);
}

// NOT_TESTED
int dns_write_question(struct dns_buffer *b, struct dns_question *question) {
	size_t s = write_labels(b, question->Name);
	writes(b, question->Type);
	writes(b, question->Class);
	return s+4;
}

// NOT_TESTED
int dns_write_questions(struct dns_buffer *b, struct dns_question **questions, size_t c_questions) {
	size_t s = 0;
	while (c_questions-- > 0)
		s += dns_write_question(b, questions[c_questions]);
	return s;
}

void dns_print_question(struct dns_question q) {
        cJSON *json = cJSON_CreateObject();
	cJSON_AddStringToObject(json, "Name" , q.Name);
	cJSON_AddNumberToObject(json, "Type" , q.Type);
	cJSON_AddNumberToObject(json, "Class", q.Class);
	printf("Question: %s\n", cJSON_Print(json));
	cJSON_Delete(json);
}

int dns_parse_records(struct dns_buffer *b, struct dns_A_record **records, int records_count) {
	StringBuilder *strb = strb_create();

	while (--records_count >= 0) {
		struct dns_A_record *record = malloc(sizeof(struct dns_A_record));
		records[records_count] = record;

		bool must_return = false;
		int  org_pos     = 0; // meant for referencing

		// the next byte is the index
		if (seekb(b) == 0xC0) {
			b->pos++;
			int target_index = getb(b);
			org_pos          = b->pos;
			b->pos      	 = target_index;
			must_return 	 = true;
		} 

		int size = parse_labels(b, strb);
		b->pos = must_return ? org_pos : b->pos;

		if (size < 0)             return -1;
		if (strb_reset(strb) < 0) return -1;

		record->Type   = gets(b);
		record->Class  = gets(b);
		record->TTL    = getl(b);
		/* record->Len */ gets(b); // I think I am supposed to identify the NS record type via it's length
		record->IPv4   = getl(b);
	}

	return strb_free(strb);
}

// NOT_TESTED
int dns_write_record(struct dns_buffer *b, struct dns_A_record *record) {
	size_t s = write_labels(b, record->Name);
	writes(b, record->Type);
	writes(b, record->Class);
	writel(b, record->TTL);
	writes(b, sizeof record->IPv4);
	writel(b, record->IPv4);
	return s+18;
}

// NOT_TESTED
int dns_write_records(struct dns_buffer *b, struct dns_A_record **records, size_t c_records) {
	size_t s = 0;
	while (c_records-- > 0)
		s += dns_write_record(b, records[c_records]);
	return s;
}

void dns_print_record(struct dns_A_record record) {
	cJSON *json = cJSON_CreateObject();

	char ipv4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &record.IPv4, ipv4, sizeof ipv4);

	cJSON_AddStringToObject(json, "Name", record.Name);
	cJSON_AddStringToObject(json, "IPv4", ipv4);
	cJSON_AddNumberToObject(json, "Type", record.Type);
	cJSON_AddNumberToObject(json, "Class", record.Class);
	cJSON_AddNumberToObject(json, "TTL", record.TTL);

	printf("A: %s\n", cJSON_Print(json));
	cJSON_Delete(json);
}

struct dns_packet *dns_new_packet(struct dns_header header) {
	struct dns_packet *packet = calloc(sizeof(struct dns_packet), 1);
	packet->header = header;
	return packet;
}

// NOT_TESTED
void dns_btop(struct dns_buffer *b, struct dns_packet *p) {
	if (dns_parse_header(b, &p->header) < 0) {
		fprintf(stderr, "could not parse header!\n");
		return;
	}

	p->questions = malloc(p->header.questions * sizeof(struct dns_question*));
	if (dns_parse_questions(b, p->questions, p->header.questions) < 0) {
		fprintf(stderr, "failed to parse questions\n");
		free(p->questions);
		return;
	}
	p->c_questions = p->header.questions;

	if (p->header.response) {
		p->answers = malloc(p->header.answers * sizeof(struct dns_A_record*));
		if (dns_parse_records(b, p->answers, p->header.answers) < 0) {
			fprintf(stderr, "failed to parse A records\n");
			free   (p->answers);
			return;
		}
		p->c_answers = p->header.answers;
	}
}

// NOT_TESTED
void dns_ptob(struct dns_packet *p, struct dns_buffer *b) {
	if (dns_write_header(p->header, b) < 0) {
		fprintf(stderr, "could not parse header!\n");
		return;
	}

	if (dns_write_questions(b, p->questions, p->c_questions) < 0) {
		fprintf(stderr, "failed to parse questions\n");
		free(p->questions);
		return;
	}

	if (p->header.response) {
		if (dns_write_records(b, p->answers, p->c_answers) < 0) {
			fprintf(stderr, "failed to parse A records\n");
			free   (p->answers);
			return;
		}
	}
}

// NOT_TESTED
int dns_pwrite_question(struct dns_packet *p, const char *domain) {
	struct dns_question *question = malloc(sizeof(struct dns_question));

	strcpy(question->Name, domain);
	question->Type  = 1;
	question->Class = 1;

	p->questions = realloc(p->questions, p->c_questions * sizeof(struct dns_question)); // okay this is actually fucked
	p->questions[p->c_questions++] = question;
	p->header.questions++;
 
	return sizeof *question;
}

// NOT_TESTED
int dns_pwrite_answer(struct dns_packet *p, const char *domain, uint32_t ipv4) {
	struct dns_A_record *record = malloc(sizeof(struct dns_A_record));
	strcpy(record->Name, domain);
	record->Type  = 1;
	record->Class = 1;
	record->TTL   = 69;
	record->IPv4  = ipv4;

	p->answers = realloc(p->answers, p->c_answers * sizeof(struct dns_A_record)); // okay this is actually fucked
	p->answers[p->c_answers++] = record;
	p->header.answers++;
 
	return sizeof *record;
}

// NOT_TESTED
void dns_pprint(struct dns_packet p) {
	dns_print_header(p.header);
	while (p.c_questions-- > 0)
		dns_print_question(*p.questions[p.c_questions]);
	while (p.c_answers-- > 0)
		dns_print_record(*p.answers[p.c_answers]);
	while (p.c_authorities-- > 0)
		dns_print_record(*p.authorities[p.c_authorities]);
	while (p.c_resources-- > 0)
		dns_print_record(*p.resources[p.c_resources]);
}

// NOT_TESTED
void dns_free_packet(struct dns_packet *p) {
	while(p->c_answers-- > 0) free(p->answers[p->c_answers]);
	free(p->answers);
	while(p->c_questions -- > 0) free(p->questions[p->c_questions]);
	free(p->questions);
	while(p->c_authorities-- > 0) free(p->authorities[p->c_authorities]);
	free(p->authorities);
	while(p->c_resources-- > 0) free(p->resources[p->c_resources]);
	free(p->resources);
}

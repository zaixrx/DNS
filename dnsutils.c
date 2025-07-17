#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/socket.h>
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

/*
static inline uint16_t gets(struct dns_buffer *b) {
	return 	((uint16_t)getb(b) << 0)|
		((uint16_t)getb(b) << 8);
}

static inline uint32_t getl(struct dns_buffer *b) {
	return htonl(
		((uint32_t)getb(b) << 0) |
		((uint32_t)getb(b) << 8) |
		((uint32_t)getb(b) << 16)|
		((uint32_t)getb(b) << 24)
	);
}
*/

static inline uint16_t gets(struct dns_buffer *b) {
	uint16_t val = ntohs(*(uint16_t*)(b->buf+b->pos)); b->pos += 2;
	return val;
}

static inline uint32_t getl(struct dns_buffer *b) {
	uint32_t val = ntohl(*(uint32_t*)(b->buf+b->pos)); b->pos += 4;
	return val;
}

static inline void getr(struct dns_buffer *b, void *d, uint8_t d_size) {
	if (b->pos + d_size >= BUFF_SIZE) return;
	if (d) memcpy(d, b->buf+b->pos, d_size);
	b->pos += d_size;
}

static inline uint8_t seekb(struct dns_buffer *p) {
	return (uint8_t)p->buf[p->pos];
}

static inline void writeb(struct dns_buffer *b, uint8_t d) {
	if (b->size + 1 >= BUFF_SIZE) return;
	b->buf[b->size] = d;
	b->size += 1;
}

static inline int writes(struct dns_buffer *b, uint16_t d) {
	if (b->size + 2 >= BUFF_SIZE) return -1;
	*(uint16_t*)(b->buf+b->size) = htons(d);
	b->size += 2;
	return 2;
}

static inline int writel(struct dns_buffer *b, uint32_t d) {
	if (b->size + 4 >= BUFF_SIZE) return -1;
	*(uint32_t*)(b->buf+b->size) = htonl(d);
	b->size += 4;
	return 4;
}

// write range
static inline int writer(struct dns_buffer *b, const void *d, size_t d_size) {
	if (b->size + d_size >= BUFF_SIZE) return -1;
	memcpy(b->buf + b->size, d, d_size);
	b->size += d_size;
	return d_size;
}

uint32_t parse_labels(struct dns_buffer *b, char *name) {
	uint8_t  label_size  = getb(b), next_len = 0;
	uint16_t buffer_size = 1, name_size = 0;
	char     label[64];

	while (label_size > 0) {
		// the next byte is the index
		if ((label_size & 0xC0) == 0xC0) {
			int org_pos = b->pos + 1;
			b->pos  = (label_size ^ 0xC0) << 8 | getb(b);
			parse_labels(b, label);
			b->pos = org_pos;
			label_size = strlen(label)+1;
			memcpy(name + name_size, label, label_size);
			label_size = 0;
			buffer_size += 2;
		} else {
			getr(b, label, label_size);
			next_len = getb(b);
			label[label_size++] = next_len > 0 ? '.' : '\0';
			buffer_size += label_size + 1;
			memcpy(name + name_size, label, label_size);
			name_size += label_size;
			label_size = next_len;
		}

	}

	return buffer_size;
}

int next_label(const char *domain, char *label, int *offset) {
	int label_size = 0;
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
		size += lsize + 1;
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

	out->rescode             = (DNSRESCode)(flags & 0xF);
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

int dns_parse_questions(struct dns_buffer *p, struct dns_question **questions, size_t questions_count) {
	while (questions_count > 0) {
		struct dns_question *question = malloc(sizeof(struct dns_question));
		questions[--questions_count] = question;

		parse_labels(p, question->Name);

		question->Type   = gets(p);
		question->Class  = gets(p);
	}	

	return 0;
}

int dns_write_question(struct dns_buffer *b, struct dns_question *question) {
	size_t s = write_labels(b, question->Name);
	s += writes(b, question->Type);
	s += writes(b, question->Class);
	return s;
}

int dns_write_questions(struct dns_buffer *b, struct dns_question **questions, size_t c_questions) {
	size_t s = 0;
	while (c_questions > 0) s += dns_write_question(b, questions[--c_questions]);
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

int dns_parse_records(struct dns_buffer *b, struct dns_record **records, size_t records_count) {
	unsigned int i = 0;
	while (i < records_count) {
		struct dns_record *record = malloc(sizeof(struct dns_record));
		records[i++] = record;

		int size = parse_labels(b, record->Name);

		record->Type   = gets(b);
		record->Class  = gets(b);
		record->TTL    = getl(b);
		
		int rd_size = gets(b);
		

		switch (record->Type) {
			case RT_A: {
				getr(b, &record->RD.A.IPv4, rd_size);
			} break;
			case RT_NS: {
				parse_labels(b, record->RD.NS.Host);
			} break;
			case RT_CNAME: {
				parse_labels(b, record->RD.CNAME.Host);
			} break;
			case RT_MX: {
				record->RD.MX.Priority = gets(b);
				parse_labels(b, record->RD.CNAME.Host);
			} break;
			case RT_AAAA: {
				getr(b, record->RD.AAAA.IPv6, sizeof record->RD.AAAA.IPv6);
			} break;
			default: { getr(b, NULL, rd_size); } break;
		}
	}

	return 0;
}

int dns_write_record(struct dns_record *record, struct dns_buffer *b) {
	size_t s = write_labels(b, record->Name);
	s += writes(b, record->Type);
	s += writes(b, record->Class);
	s += writel(b, record->TTL);

	int rlen = 0; bool ret = false;

	switch (record->Type) {
		case RT_A: {
			s += writes(b, sizeof record->RD.A.IPv4);
			s += writel(b, record->RD.A.IPv4);
		} break;
		case RT_NS: {
			ret = true;
			s += writes(b, 0); // reserve storage
			s += rlen = write_labels(b, record->RD.NS.Host);
		} break;
		case RT_CNAME: {
			ret = true;
			s += writes(b, 0); // reserve storage
			s += rlen = write_labels(b, record->RD.CNAME.Host);	
		} break;
		case RT_MX: {
			ret = true;
			s += writes(b, 0); // reserve storage
			s += rlen  = writes(b, record->RD.MX.Priority);
			s += rlen += write_labels(b, record->RD.CNAME.Host);
		} break;
		case RT_AAAA: {
			uint16_t size = sizeof record->RD.AAAA.IPv6;
			writes(b, size);
			writer(b, record->RD.AAAA.IPv6, size);
		} break;
		default: { /* TODO: do some error handeling */ } break;
	}

	if (ret) {
		b->pos -= rlen + 2;
		writes(b, rlen); // it'll overwrite old data
		b->pos += rlen + 2;
	}

	return s;
}

int dns_write_records(struct dns_buffer *b, struct dns_record **records, size_t c_records) {
	size_t s = 0;
	while (c_records > 0) s += dns_write_record(records[--c_records], b);
	return s;
}

void dns_print_record(struct dns_record record) {
	cJSON *json = cJSON_CreateObject();
	
	cJSON_AddStringToObject(json, "Name", record.Name);
	switch (record.Type) {
		case RT_A: {
			char ipv4[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &record.RD.A.IPv4, ipv4, sizeof ipv4);
			cJSON_AddStringToObject(json, "IPv4", ipv4);
			cJSON_AddStringToObject(json, "Type", "A");
		} break;
		case RT_NS: {
			cJSON_AddStringToObject(json, "Host", record.RD.NS.Host);
			cJSON_AddStringToObject(json, "Type", "NS");
		} break;
		case RT_CNAME: {
			cJSON_AddStringToObject(json, "Host", record.RD.CNAME.Host);
			cJSON_AddStringToObject(json, "Type", "CNAME");
		} break;
		case RT_MX: {
			cJSON_AddNumberToObject(json, "Priority", record.RD.MX.Priority);
			cJSON_AddStringToObject(json, "Host", record.RD.MX.Host);
			cJSON_AddStringToObject(json, "Type", "MX");
		} break;
		case RT_AAAA: {
			char ipv6[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &record.RD.AAAA.IPv6, ipv6, sizeof ipv6);
			cJSON_AddStringToObject(json, "IPv6", ipv6);
			cJSON_AddStringToObject(json, "Type", "AAAA");
		} break;
		default: {
			cJSON_AddStringToObject(json, "Type", "Unknown");
		} break;
	}
	cJSON_AddNumberToObject(json, "Class", record.Class);
	cJSON_AddNumberToObject(json, "TTL", record.TTL);

	printf("Record: %s\n", cJSON_Print(json));

	cJSON_Delete(json);
}

void dns_btop(struct dns_buffer *b, struct dns_packet *p) {
	memset(p, 0, sizeof *p);

	if (dns_parse_header(b, &p->header) < 0) {
		fprintf(stderr, "could not parse header!\n");
		return;
	}

	if (p->header.questions > 0) {
		p->questions = malloc(p->header.questions * sizeof(struct dns_question*));
		if (dns_parse_questions(b, p->questions, p->header.questions) < 0) {
			fprintf(stderr, "failed to parse questions\n");
			free(p->questions);
			return;
		}
		p->c_questions = p->header.questions;
	}

	if (p->header.answers > 0) {
		p->answers = malloc(p->header.answers * sizeof(struct dns_record*));
		if (dns_parse_records(b, p->answers, p->header.answers) < 0) {
			fprintf(stderr, "failed to parse A records\n");
			free   (p->answers);
			return;
		}
		p->c_answers = p->header.answers;
	}

        if (p->header.authoritative_entries > 0) {
		p->authorities = malloc(p->header.authoritative_entries * sizeof(struct dns_record*));
		if (dns_parse_records(b, p->authorities, p->header.authoritative_entries) < 0) {
			fprintf(stderr, "failed to parse A records\n");
			free   (p->authorities);
			return;
		}
		p->c_authorities = p->header.authoritative_entries;
	}

	if (p->header.resource_entries > 0) {
		p->resources = malloc(p->header.resource_entries * sizeof(struct dns_record*));
		if (dns_parse_records(b, p->resources, p->header.resource_entries) < 0) {
			fprintf(stderr, "failed to parse A records\n");
			free   (p->resources);
			return;
		}
		p->c_resources = p->header.resource_entries;
	}
}

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

	if (dns_write_records(b, p->answers, p->c_answers) < 0) {
		fprintf(stderr, "failed to parse A records\n");
		free   (p->answers);
		return;
	}

	if (dns_write_records(b, p->authorities, p->c_authorities) < 0) {
		fprintf(stderr, "failed to parse A records\n");
		free   (p->authorities);
		return;
	}

	if (dns_write_records(b, p->resources, p->c_resources) < 0) {
		fprintf(stderr, "failed to parse A records\n");
		free   (p->resources);
		return;
	}
}

int dns_pwrite_question(struct dns_packet *p, struct dns_question q) {
	struct dns_question *question = malloc(sizeof(struct dns_question)); *question = q;
	size_t memsize = (p->c_questions + 1) * sizeof(struct dns_question);
	p->questions = p->questions ? realloc(p->questions, memsize) : malloc(memsize); // okay... this is fucked
	p->questions[p->c_questions] = question;

	p->header.questions++;
	p->c_questions++;

	return sizeof *question;
}

int dns_pwrite_A_answer(struct dns_packet *p, const char *domain, uint32_t ipv4) {
	struct dns_record *record = malloc(sizeof(struct dns_record));
	strcpy(record->Name, domain);
	record->Type  = 1;
	record->Class = 1;
	record->TTL   = 69;
	record->RD.A.IPv4  = ipv4;

	p->answers = realloc(p->answers, p->c_answers * sizeof(struct dns_record)); // okay this is actually fucked
	p->answers[p->c_answers++] = record;
	p->header.answers++;
 
	return sizeof *record;
}

void dns_pprint(struct dns_packet p) {
	dns_print_header(p.header);
	while (p.c_questions > 0) dns_print_question(*p.questions[--p.c_questions]);
	while (p.c_answers > 0) dns_print_record(*p.answers[--p.c_answers]);
	while (p.c_authorities > 0) dns_print_record(*p.authorities[--p.c_authorities]);
	while (p.c_resources > 0) dns_print_record(*p.resources[--p.c_resources]);
}

void dns_free_packet(struct dns_packet *p) {
	while(p->c_answers > 0) free(p->answers[--p->c_answers]);
	free(p->answers);
	while(p->c_questions > 0) free(p->questions[--p->c_questions]);
	free(p->questions);
	while(p->c_authorities > 0) free(p->authorities[--p->c_authorities]);
	free(p->authorities);
	while(p->c_resources > 0) free(p->resources[--p->c_resources]);
	free(p->resources);
	bzero(p, sizeof(struct dns_packet));
}

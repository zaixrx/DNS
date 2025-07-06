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

uint8_t getb(struct dns_buffer *p) {
	return (uint8_t)p->buf[p->pos++];
}

// little endian processors only bruv skee
uint16_t gets(struct dns_buffer *p) {
	return ((uint16_t)getb(p) << 8) | getb(p);
}

uint32_t getl(struct dns_buffer *p) {
	return ((uint32_t)getb(p) << 24) |
	       ((uint32_t)getb(p) << 16) |
	       ((uint32_t)getb(p) << 8)  | getb(p);
}

uint8_t seekb(struct dns_buffer *p) {
	return (uint8_t)p->buf[p->pos];
}

int parse_header(struct dns_buffer *p, struct header *out) {
	if (!(out && p)) return -1;

	out->id = gets(p);

	uint16_t flags = gets(p);

	uint8_t  first = flags & 0xF;
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

	out->questions = gets(p);
	out->answers   = gets(p);
	out->authoritative_entries = gets(p);
	out->resource_entries      = gets(p);

	return HEADER_SIZE;
}

void print_header(struct header h) {
	cJSON *json = cJSON_CreateObject();
	cJSON_AddNumberToObject(json, "id", h.id);

	cJSON *flags = cJSON_CreateObject();
	cJSON_AddNumberToObject(flags, "rescode" , h.rescode);
	cJSON_AddBoolToObject  (flags, "checking disabled", h.checking_disabled);
	cJSON_AddNumberToObject(flags, "authed data", h.authed_data);
	cJSON_AddNumberToObject(flags, "z", h.z);
	cJSON_AddNumberToObject(flags, "recursion available", h.recursion_available);
	cJSON_AddNumberToObject(flags, "truncated message", h.truncated_message);
	cJSON_AddNumberToObject(flags, "opcode", h.opcode);
	cJSON_AddNumberToObject(flags, "response", h.response);
	cJSON_AddItemToObject(json, "flags", flags);

	cJSON_AddNumberToObject(json, "questions", h.questions);
	cJSON_AddNumberToObject(json, "answers"  , h.answers);
	cJSON_AddNumberToObject(json, "authoritative entries", h.authoritative_entries);
	cJSON_AddNumberToObject(json, "resource entries", h.resource_entries);

	printf("Header: %s\n", cJSON_Print(json));

	cJSON_Delete(json);
}

uint32_t parse_labels(struct dns_buffer *p, StringBuilder *strb) {
	char    *buf  = p->buf+p->pos;
	uint8_t  len  = *buf++, next_len = 0;
	uint32_t size = 0;

	while (len > 0) {
		next_len = *(buf+len);
		*(buf+len) = '\0';

		if (strb_append(strb, buf) < 0) return -1;
		*(buf+len) = next_len; // learned that the hard way

		buf  += len+1;
		size += len+1;
		len   = next_len;
	}

	p->pos += size+1;
	return size+1;
}

int parse_questions(struct dns_buffer *p, struct question **questions, int questions_count) {
	StringBuilder *strb = strb_create();

	while (questions_count-- > 0) {
		struct question *question = malloc(sizeof(struct question));
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

void print_question(struct question q) {
        cJSON *json = cJSON_CreateObject();
	cJSON_AddStringToObject(json, "Name" , q.Name);
	cJSON_AddNumberToObject(json, "Type" , q.Type);
	cJSON_AddNumberToObject(json, "Class", q.Class);
	printf("Question: %s\n", cJSON_Print(json));
	cJSON_Delete(json);
}

int parse_A_records(struct dns_buffer *p, struct A_record **records, int records_count) {
	StringBuilder *strb = strb_create();

	while (--records_count >= 0) {
		struct A_record *record = malloc(sizeof(struct A_record));
		records[records_count] = record;

		bool must_return = false;
		int  org_pos     = 0; // meant for referencing

		printf("%d\n", org_pos);

		// the next byte is the index
		if (seekb(p) == 0xC0) {
			p->pos++;
			int target_index = getb(p);
			org_pos          = p->pos;
			p->pos      	 = target_index;
			must_return 	 = true;
		} 

		int size = parse_labels(p, strb);
		p->pos = must_return ? org_pos : p->pos;

		if (size < 0)             return -1;
		if (strb_reset(strb) < 0) return -1;

		record->Type   = gets(p);
		record->Class  = gets(p);
		record->TTL    = getl(p);
		record->Len    = gets(p); // I think I am supposed to identify the NS record type via it's length
		uint32_t nipv4 = ntohl(getl(p));

		inet_ntop(AF_INET, &nipv4, record->IPv4, sizeof record->IPv4);
	}

	return strb_free(strb);
}

void print_record(struct A_record record) {
	cJSON *json = cJSON_CreateObject();

	cJSON_AddStringToObject(json, "Name", record.Name);
	cJSON_AddStringToObject(json, "IPv4", record.IPv4);
	cJSON_AddNumberToObject(json, "Type", record.Type);
	cJSON_AddNumberToObject(json, "Class", record.Class);
	cJSON_AddNumberToObject(json, "TTL", record.TTL);

	printf("A: %s\n", cJSON_Print(json));
	cJSON_Delete(json);
}

int create_dns_packet(struct dns_buffer *p, struct dns_packet *out) {
	bzero(out, sizeof(struct dns_packet));

	struct header *header = &out->header;
	if (parse_header(p, header) < 0) {
		fprintf(stderr, "could not parse header!\n");
		return EXIT_FAILURE;
	}

	out->questions = malloc(header->questions * sizeof(struct question*));
	if (parse_questions(p, out->questions, header->questions) < 0) {
		fprintf(stderr, "failed to parse questions\n");
		free(out->questions);
		return -1;
	}
	out->c_questions = header->questions;

	if (header->response) {
		out->answers = malloc(header->answers * sizeof(struct A_record*));
		if (parse_A_records(p, (struct A_record**)out->answers, header->answers) < 0) {
			fprintf(stderr, "failed to parse A records\n");
			free   (out->answers);
			return EXIT_FAILURE;
		}
		out->c_answers = header->answers;
	}

	return EXIT_SUCCESS;
}

void free_dns_packet(struct dns_packet *p) {
	while(p->c_answers-- > 0) free(p->answers[p->c_answers]);
	free(p->answers);

	while(p->c_questions -- > 0) free(p->questions[p->c_questions]);
	free(p->questions);

	while(p->c_authorities-- > 0) free(p->authorities[p->c_authorities]);
	free(p->authorities);

	while(p->c_resources-- > 0) free(p->resources[p->c_resources]);
	free(p->resources);
}

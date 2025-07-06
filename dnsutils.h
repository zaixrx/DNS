#ifndef TYPES_H
#define TYPES_H

#include "sb.h"
#include <stdbool.h>
#include <arpa/inet.h>

#define BUFF_SIZE 512
#define NAME_SIZE 64
#define HEADER_SIZE 12

struct dns_buffer {
	char buf[BUFF_SIZE];
	int  pos;
	int  size;
};

typedef enum {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
} ResultCode;

struct header {
	uint16_t id;

    	bool recursion_desired;
    	bool truncated_message;
    	bool authoritative_answer;
    	uint8_t opcode;
    	bool response;
	ResultCode rescode;
    	bool checking_disabled;
    	bool authed_data;
    	bool z;
    	bool recursion_available;

    	uint16_t questions;
    	uint16_t answers;
    	uint16_t authoritative_entries;
    	uint16_t resource_entries;
};

struct question {
	char     Name[NAME_SIZE];
	uint16_t Type;
	uint16_t Class;
};

struct record {
	char     Name[NAME_SIZE];
	uint16_t Type;
	uint16_t Class;
	uint32_t TTL;
	uint16_t Len;
	char     D[];
};

struct A_record {
	char     Name[NAME_SIZE];
	uint16_t Type;
	uint16_t Class;
	uint32_t TTL;
	uint16_t Len;
	char     IPv4[INET_ADDRSTRLEN];
};

struct dns_packet {
	struct header     header;
	struct question **questions;
	size_t c_questions;
	struct record   **answers;
	size_t c_answers;
	struct record   **authorities;
	size_t c_authorities;
	struct record   **resources;
	size_t c_resources;
};

uint16_t gets(struct dns_buffer *p);
uint32_t getl(struct dns_buffer *p);
uint8_t seekb(struct dns_buffer *p);

uint8_t consume_flag(uint16_t *flags, int len);
int parse_header(struct dns_buffer *p, struct header *out);
void print_header(struct header h);

uint32_t parse_labels(struct dns_buffer *p, StringBuilder *strb);
int parse_questions(struct dns_buffer *p, struct question **questions, int questions_count);
void print_question(struct question q);
int parse_A_records(struct dns_buffer *p, struct A_record **records, int records_count);
void print_record(struct A_record record);

int create_dns_packet(struct dns_buffer *p, struct dns_packet *out);
void free_dns_packet(struct dns_packet *p);

#endif

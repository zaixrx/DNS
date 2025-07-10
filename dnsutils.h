#ifndef TYPES_H
#define TYPES_H

#include <netinet/in.h>
#include <stdbool.h>
#include <arpa/inet.h>

#define BUFF_SIZE 512
#define NAME_SIZE 64
#define HEADER_SIZE 12

// RFC pages refer to Record as RR(Resource Record)

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

struct dns_header {
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

struct dns_question {
	char     Name[NAME_SIZE];
	uint16_t Type;
	uint16_t Class;
};

typedef enum {
	RT_UNKNOWN,
	RT_A,
	RT_NS,
	RT_CNAME = 5,
	RT_MX = 15,
	RT_AAAA = 28,
} RecordType;

typedef enum {
	RC_UNKNOWN,
	RC_IN,
} RecordClass;

struct dns_record {
	char        Name[NAME_SIZE];
	RecordType  Type;
	RecordClass Class;
	uint32_t    TTL;
	uint16_t    RDLENGTH;	
	union {
		struct {
			in_addr_t IPv4;
		} A;
		struct {
			char Host[NAME_SIZE];
		} NS;
		struct {
			char Host[NAME_SIZE];
		} CNAME;
		struct {
			uint16_t Priority;
			char Host[NAME_SIZE];
		} MX;
		struct {
			uint8_t IPv6[16];
		} AAAA;
	} RD;
};

struct dns_packet {
	struct dns_header     header;
	struct dns_question **questions;
	size_t c_questions;
	struct dns_record   **answers;
	size_t c_answers;
	struct dns_record   **authorities;
	size_t c_authorities;
	struct dns_record   **resources;
	size_t c_resources;
};

void dns_print_header  (struct dns_header     header);
void dns_print_question(struct dns_question question);
void dns_print_record  (struct dns_record   record);
void dns_print_packet  (struct dns_packet packet);

struct dns_packet *dns_new_packet(struct dns_header header);
void dns_free_packet(struct dns_packet *p);

// dns_buffer to dns_packet, you have the responsibilty of managing memory
void dns_btop(struct dns_buffer *b, struct dns_packet *p);
// dns_packet to dns_buffer, you have the responsibilty of managing memory
void dns_ptob(struct dns_packet *p, struct dns_buffer *b);

int dns_pwrite_question(struct dns_packet *p, const char *domain);
int dns_pwrite_answer(struct dns_packet *p, const char *domain, uint32_t ipv4);
void dns_pprint         (struct dns_packet p);

#endif

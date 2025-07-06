#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>

#define BUFF_SIZE 512
#define NAME_SIZE 64

struct packet {
	char buf[BUFF_SIZE];
	int  pos;
	int  size;
};

struct flags {
	char RCODE;
	char Z;
	char RA;
	char RD;
	char TC;
	char AA;
	char OPCODE;
	char QR;
};

struct header {
	uint16_t     ID;
	struct flags flags;
	uint16_t     qd_count;
	uint16_t     an_count;
	uint16_t     ns_count;
	uint16_t     ar_count;
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
	char     Data[];
};

#include <arpa/inet.h>

struct A_record {
	char     Name[NAME_SIZE];
	uint16_t Type;
	uint16_t Class;
	uint32_t TTL;
	uint16_t Len;
	char     IPv4[INET_ADDRSTRLEN];
};

#endif

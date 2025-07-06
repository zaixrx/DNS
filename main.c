#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#include "sb.h"
#include "types.h"

#define HEADER_SIZE 12

// gets the next byte in buf with incrementing pos
uint8_t getb(struct packet *p) {
	return (uint8_t)p->buf[p->pos++];
}

// little endian processors only bruv skee
uint16_t gets(struct packet *p) {
	return ((uint16_t)getb(p) << 8) | getb(p);
}

uint32_t getl(struct packet *p) {
	return ((uint32_t)getb(p) << 24) |
	       ((uint32_t)getb(p) << 16) |
	       ((uint32_t)getb(p) << 8)  | getb(p);
}

uint8_t consumeFlag(uint16_t *flags, int len) {
	uint8_t ret = *flags & (1 << (len - 1));
	*flags >>= len;
	return ret;
}

int parseHeaderFlags(uint16_t buf, struct flags *f) {
	f->RCODE  = consumeFlag(&buf, 4);
	f->Z      = consumeFlag(&buf, 3);
	f->RA     = consumeFlag(&buf, 1);
	f->RD     = consumeFlag(&buf, 1);
	f->TC     = consumeFlag(&buf, 1);
	f->AA     = consumeFlag(&buf, 1);
	f->OPCODE = consumeFlag(&buf, 4);
	f->QR     = consumeFlag(&buf, 1);

	return 0;
}

void printFlags(struct flags f) {
	printf("RCODE: %d\nZ: %d\nRA: %d\nRD: %d\nTC: %d\nAA: %d\nOPCODE: %d\nQR: %d\n", f.RCODE, f.Z, f.RA, f.RD, f.TC, f.AA, f.OPCODE, f.QR);
}

int parseHeader(struct packet *p, struct header *out) {
	if (!(out && p)) return -1;

	out->ID = gets(p);
	if (parseHeaderFlags(gets(p), &out->flags) < 0) return -1;
	out->qd_count = gets(p);
	out->an_count = gets(p);
	out->ns_count = gets(p);
	out->ar_count = gets(p);

	return HEADER_SIZE;
}

void printHeader(struct header h) {
	printf("ID: %d\n", h.ID);
	printFlags(h.flags);
	printf("QDCOUNT: %d\n", h.qd_count);
	printf("ANCOUNT: %d\n", h.an_count);
	printf("NSCOUNT: %d\n", h.ns_count);
	printf("ARCOUNT: %d\n", h.ar_count);
}

uint32_t parse_label(struct packet *p, StringBuilder *strb) {
	char    *buf  = p->buf+p->pos;
	uint8_t  len  = *buf++, next_len = 0;
	uint32_t size = 0;

	while (len > 0) {
		next_len = *(buf+len);
		*(buf+len) = '\0';
		printf("c:%d,n:%d,s:%s\n", len, next_len, buf);

		if (strb_append(strb, buf) < 0) return -1;
		*(buf+len) = next_len; // learned that the hard way

		buf  += len+1;
		size += len+1;
		len   = next_len;
	}

	p->pos += size+1;
	printf("pos: %d\n", p->pos);
	return size+1;
}

// I swear the god if that works first glance, I'll fucking jump out of the fucking window
// FUCK! it didn't actually work
// now it works!
int parse_question(struct packet *p, struct question *out) {
	StringBuilder *strb = strb_create();
	int read_bytes = parse_label(p, strb);
	if (read_bytes < 0) return -1;
	if (strb_concat(strb, out->Name) < 0) return -1;
	if (strb_free(strb) < 0) return -1;

	out->Type = gets(p);
	out->Class = gets(p);

	return read_bytes;
}

#include <arpa/inet.h>

int parse_A_record(struct packet *p, struct A_record *record) {
	// StringBuilder *strb = strb_create();

	uint8_t ptr = getb(p);
	printf("length pointer: %d %#x\n", p->pos, ptr);

	if (ptr == 0xC0) {
		int new_index = getb(p);
		int org_pos= p->pos;

		p->pos = new_index;

		StringBuilder *strb = strb_create();
		int read_bytes = parse_label(p, strb);
		if (read_bytes < 0) return -1;
		printf("here\n");
		if (strb_concat(strb, record->Name) < 0) return -1;
		printf("here\n");
		if (strb_free(strb) < 0) return -1;

		printf("original: %d, actual: %d\n", org_pos, p->pos);
		p->pos = org_pos;
	}

	record->Type  = gets(p);
	record->Class = gets(p);
	record->TTL   = getl(p);
	record->Len   = gets(p); // I think I am supposed to identify the NS record type via it's length
	uint32_t nipv4 = ntohl(getl(p));

	inet_ntop(AF_INET, &nipv4, record->IPv4, sizeof record->IPv4);

	printf("str: %s, type: %d, class %d, TTL: %d, IPv4: %s\n", record->Name, record->Type, record->Class, record->TTL, record->IPv4);

	return 0;
}

int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "usage: %s <header>\n", argv[0]);
		return 1;
	}

	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "couldn't open file %s\n", argv[1]);
		return 1;
	}

	struct packet p = {0};
	if ((p.size = read(fd, p.buf, BUFF_SIZE)) < 0) {
		fprintf(stderr, "couldn't read from opened file %s\n", argv[1]);
		return 1;
	}
	close(fd);

	struct header h = {0};
	if (parseHeader(&p, &h) < 0) {
		fprintf(stderr, "could not parse header!\n");
		return -1;
	}
	printHeader(h);

	struct question q = {0};
	int question_size = parse_question(&p, &q);
	printf("%s %d %d\n", q.Name, q.Type, q.Class);

	printf("read size %d - should I continue? %d\n", p.pos, h.flags.QR);
	if (h.flags.QR) {
		printf("parsing a records\n");
		struct A_record record = {0};
		parse_A_record(&p, &record);
	}

	return 0;
}

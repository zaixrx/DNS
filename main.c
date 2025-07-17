#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include "dnsutils.h"

#define HTABLE_IMPLEMENTATION
#include "hashtable.h"

#define ADDR_IN6 struct sockaddr_in6
#define ADDR_IN  struct sockaddr_in
#define ADDR     struct sockaddr
#define ADDR_LEN socklen_t 

#define PORT 12000
#define ADDRESS "0.0.0.0"
#define MAX_RETRIES 10
#define MAX_RESOLUTION_ITERATIONS 20
#define _RETRANSMISSION_INTERVAL 2 // seconds
#define SOCK_IO_TIMEOUT 10
#define DO_LOG 

struct IPView {
	union {
		ADDR_IN  ipv4;
		ADDR_IN6 ipv6;
	} ip;
	enum {
		_IPv4,
		_IPv6,
	} ip_version;
};

// TODO: store these in a configuration file
char root_servers[][INET_ADDRSTRLEN] = {
	"198.41.0.4",
	"170.247.170.2",
	"192.33.4.12",
	"199.7.91.13",
	"192.203.230.10",
	"192.5.5.241",
	"192.112.36.4",
	"198.97.190.53",
	"192.36.148.17",
	"192.58.128.30",
	"193.0.14.129",
	"199.7.83.42",
	"202.12.27.33",
};
int sockfd;
// TODO: use this as a cache
// HashTable hs;

uint32_t resolve(char *qname, DNSRType qtype, DNSRESCode *rescode);
int query_ns(struct dns_buffer *buf_view, struct dns_packet *packet, struct IPView ipv);
int extract_best_ipv4(struct dns_packet *packet, struct IPView *ipv, DNSRESCode *rescode);

// TODO: place these in a seperate TU
// START_GARBAGE
static inline void log_info (const char *msg) {
	fprintf(stdout, "INFO: %s\n", msg);
}

static inline void log_error(const char *msg) {
	fprintf(stderr, "ERROR: %s\n", msg);
}

static inline void entry_presentation() {
	printf("making pancakes making making pancakes\n");
	printf("take some bacon, and I'll put it in the pancake\n");
	printf("making pancackes that's what it's gonna make\n");
	printf("making panckaaaaakes\n");
}

void write_file(const char *filepath, struct dns_buffer *buf) {
	FILE *fp;
	fp = fopen(filepath, "w+");
	fwrite(buf->buf, buf->size, 1, fp);
	fclose(fp);
}

int rrand() { // real random
	srand(time(NULL));
	return rand();
}

ADDR_IN getaddr(const char *saddr, uint16_t port) {
	ADDR_IN addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, saddr, &addr.sin_addr.s_addr);
	return addr;
}

void check(bool is_error, const char *err_msg) {
	 if (is_error) {
		 log_error(err_msg);
		 exit(EXIT_FAILURE);
	 }
}

void print_ipv4(uint32_t ipv4) {
	char outstr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ipv4, outstr, INET_ADDRSTRLEN);
	log_info(outstr);
}
// END_GARBAGE

void handle_client(struct dns_packet *packet, ADDR *addr) {
	if (packet == NULL || addr == NULL) return;
	struct dns_packet rpacket = {0};
	rpacket.header = (struct dns_header) {
		.id = packet->header.id,
		.rescode = FORMERR,
		.recursion_available = true,
	};
	// TODO: Handle multiple questions
	if (packet->c_questions > 0) {
		struct dns_question question = *packet->questions[0]; uint32_t ipv4;
		if ((ipv4 = resolve(question.Name, question.Type, &rpacket.header.rescode)) < 0) {
			print_ipv4(ipv4);
			dns_pwrite_answer(&rpacket, question.Name, ipv4); // TODO: might fail
		}
	}
	rpacket.header.id = packet->header.id;
	rpacket.header.response = true;
	rpacket.header.recursion_available = true;
	struct dns_buffer buf = {0};
	dns_ptob(&rpacket, &buf); // TODO: might fail
	// TODO: can this fail?
	sendto(sockfd, buf.buf, buf.size, 0, addr, sizeof *addr);
}

int main(void) {
	entry_presentation();

	check((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0, "failed opening socket file descriptor\n");

	int reuseaddropt = 1;
	check (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddropt, sizeof reuseaddropt) < 0, "failed configuring socket REUSEADDR\n");

	ADDR_IN sock_addr = getaddr(ADDRESS, PORT);
	check(bind(sockfd, (ADDR*)&sock_addr, sizeof sock_addr) < 0, "could not datagram socket\b");

	for (;;) {
		log_info("waiting for a user...");

		struct dns_buffer buf_view = {0};
		struct dns_packet packet   = {0};
		ADDR     client_addr = {0};
		ADDR_LEN client_addrlen = sizeof client_addr;

		// TODO: create new socket
		// read client packet
		check((buf_view.size = recvfrom(sockfd, buf_view.buf, sizeof buf_view.buf, 0, (ADDR*)&client_addr, &client_addrlen)) < 0, "failed while reading query\n");
		dns_btop(&buf_view, &packet);

		handle_client(&packet, &client_addr);
	}

	return EXIT_FAILURE;
}

void base_packet_init(struct dns_packet *packet, char *qname, DNSRType qtype) {
	dns_free_packet(packet);
	packet->header.id = rrand() % 0xFFFF; // to make it fit into a uint16_t
	struct dns_question question = {
		.Type = qtype,
		.Class = RC_IN, // only support IP
	};
	memcpy(question.Name, qname, strlen(qname)+1);
	dns_pwrite_question(packet, question);
}

uint32_t resolve(char *qname, DNSRType qtype, DNSRESCode *rescode) {
	struct IPView ipv = {0};
	struct dns_packet packet = {0};
	struct dns_buffer buffer = {0};
	for (int i = 0; i < MAX_RESOLUTION_ITERATIONS; ++i) {
		if (extract_best_ipv4(&packet, &ipv, rescode) < 0) return -1; 
		base_packet_init(&packet, qname, qtype);
		if (query_ns(&buffer, &packet, ipv) < 0) continue;  // PARTIAL_FAIL: couldn't query_ns
		dns_btop(&buffer, &packet); // TODO: may fail
#ifdef DO_LOG
		printf("---- step: %d ----\n", i);
		dns_pprint(packet);
#endif
		if (packet.header.rescode > NOERROR) {
			*rescode = packet.header.rescode;
			return -1;
		}
		if (packet.c_answers > 0) {
			for (int j = 0; j < packet.c_answers; ++j) {
				struct dns_record *answer = packet.answers[j];
				if (answer->Type != qtype) continue;
				switch (qtype) {
					case RT_A: {
						*rescode = NOERROR;
						return answer->RD.A.IPv4;
					} break;
					default: {
						*rescode = NOTIMP;
						return -1;
					} break;
				}
			}
		}
	}
	*rescode = SERVFAIL;
	return -1;
}

// packet is expected to be trimmed
int query_ns(struct dns_buffer *buf_view, struct dns_packet *packet, struct IPView ipv) {
	ADDR addr = {0};
	switch (ipv.ip_version) {
		case _IPv4: {
			addr = *(ADDR*)&ipv.ip.ipv4;
		} break;
		// TODO: Add IPv6 support
		default: {
			log_error("unsupported IP address");
		} return -1;
	}
	memset(buf_view, 0, sizeof *buf_view);
	dns_ptob(packet, buf_view); // TODO: this may fail
	int retries;
	for (retries = 0; retries < MAX_RETRIES; ++retries) {
		if (retries > 0) sleep(_RETRANSMISSION_INTERVAL);
		if (sendto(sockfd, &buf_view->buf, buf_view->size, 0, &addr, sizeof addr) < 0) {
			log_error("failed to send query");
			continue;
		}
		socklen_t addrlen = sizeof ipv.ip.ipv4;
		buf_view->size = recvfrom(sockfd, buf_view->buf, sizeof buf_view->buf, 0, (ADDR*)&ipv.ip.ipv4, &addrlen);
		if (buf_view->size < 0) {
			log_error("failed to receive response");
			continue;
		}
		break;
	}
	return retries == MAX_RETRIES ? -1 : 0;
}

int extract_best_ipv4(struct dns_packet *packet, struct IPView *ipv, DNSRESCode *rescode) {
	struct dns_record *rr = NULL;
	if (packet->c_resources > 0) {
		for (int i = 0; i < packet->c_resources; ++i) {
			rr = packet->resources[i];
			if (rr->Type == RT_A) {
				ipv->ip_version = _IPv4;
				memset(&ipv->ip.ipv4, 0, sizeof ipv->ip.ipv4);
				ipv->ip.ipv4.sin_family = AF_INET;
				ipv->ip.ipv4.sin_port   = ntohs(53);
				ipv->ip.ipv4.sin_addr.s_addr = rr->RD.A.IPv4;
				return 0;
			}
		}
	} else if (packet->c_authorities > 0) {
		for (int i = 0; i < packet->c_authorities; ++i) {
			rr = packet->authorities[i];
			if (rr->Type == RT_NS) {
				uint32_t addr = resolve(rr->RD.NS.Host, RT_A, rescode);
				if (addr < 0) continue;
				ipv->ip_version = _IPv4;
				ipv->ip.ipv4.sin_family = AF_INET;
				ipv->ip.ipv4.sin_port   = ntohs(53);
				ipv->ip.ipv4.sin_addr.s_addr = addr;
				return 0;
			}
		}
		*rescode = SERVFAIL;
		return -1;
	}
	ipv->ip_version = _IPv4;
	ipv->ip.ipv4 = getaddr(root_servers[rrand() % 13], 53);
	return 0;
}

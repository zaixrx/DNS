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

#define PORT 12000
#define ADDRESS "0.0.0.0"
#define MAX_RETRIES 10
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
HashTable hs;
int sockfd;

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
// END_GARBAGE

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

// only maintain header and one question
// TODO: make it support multiple questions
void trim_packet(struct dns_packet *packet) {
	struct dns_header header = { .id = packet->header.id };
	struct dns_question question = *packet->questions[0];
	dns_free_packet(packet);
	packet->header = header;
	dns_pwrite_question(packet, question);
}

uint32_t resolve(struct dns_buffer *buf_view, struct dns_packet *packet, int i);

struct IPView extract_best_ipv4(struct dns_packet *packet) {
	struct IPView ipv = {0};

	struct dns_record *rr = NULL;
	if (packet->c_resources > 0) {
		for (int i = 0; i < packet->c_resources; ++i) {
			rr = packet->resources[i];

			if (rr->Type == RT_A) {
				ipv.ip_version = _IPv4;

				memset(&ipv.ip.ipv4, 0, sizeof ipv.ip.ipv4);
				ipv.ip.ipv4.sin_family = AF_INET;
				ipv.ip.ipv4.sin_port   = ntohs(53);
				ipv.ip.ipv4.sin_addr.s_addr = rr->RD.A.IPv4;

				return ipv;
			}

			// TODO: support IPv6
		}
	} else if (packet->c_authorities > 0) {
		log_info("could not find glued A record");
		for (int i = 0; i < packet->c_authorities; ++i) {
			rr = packet->authorities[i];

			if (rr->Type == RT_NS) {
				struct dns_buffer buf_view = {0};
				struct dns_packet packet    = {0};
				packet.header = (struct dns_header){
					.id = 69,
				};
				struct dns_question question = {
					.Type = RT_A,
					.Class = 1
				};
				memcpy(question.Name, rr->RD.NS.Host, sizeof rr->RD.NS.Host);
				dns_pwrite_question(&packet, question);
				// you need some sort of state machine
				// to get the current ns
				log_info("starting resolve parallel process for NS record");
				uint32_t addr = resolve(&buf_view, &packet, 0);
				if (addr < 0) {
					log_error("failed to resolve NS record");
					continue;
				}
				log_info("found IPv4 address for NS record");
				ipv.ip_version = _IPv4;
				memset(&ipv.ip.ipv4, 0, sizeof ipv.ip.ipv4);
				ipv.ip.ipv4.sin_family = AF_INET;
				ipv.ip.ipv4.sin_port   = ntohs(53);
				ipv.ip.ipv4.sin_addr.s_addr = rr->RD.A.IPv4;

				return ipv;
			}

			// TODO: support IPv6
		}
	} 

	log_info("could not find useful info, starting over");
	srand(time(NULL));
	ipv.ip_version = _IPv4;
	ipv.ip.ipv4 = getaddr(root_servers[rand() % 13], 53);

	return ipv;
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

	dns_ptob(packet, buf_view);

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

		log_info("successfully issued query");
		break;
	}

	return retries == MAX_RETRIES ? -1 : 0;
}

uint32_t resolve(struct dns_buffer *buf_view, struct dns_packet *packet, int i) {
	struct IPView ipv = extract_best_ipv4(packet);

	memset(buf_view, 0, sizeof *buf_view);
	trim_packet(packet);

	if (query_ns(buf_view, packet, ipv) < 0) return -1; // query_ns does logging

	dns_btop(buf_view, packet);

#ifdef DO_LOG
	printf("step: %d\n", i);
	dns_pprint(*packet);
#endif

	struct dns_question *question = packet->questions[0];
	if (question == NULL) {
		log_error("no questions provided");
		return -1;
	}

	for (int i = 0; i < packet->c_answers; ++i) {
		struct dns_record *answer = packet->answers[i];
		if (answer->Type != question->Type) continue;
		switch (question->Type) {
			case RT_A: {
				return answer->RD.A.IPv4;
			} break;
			default: {
				log_error("unsupported query type"); // I think that must come early
				return -1;
			} break;
		}
	}

	return resolve(buf_view, packet, ++i);
}

int main(void) {
	entry_presentation();

	check((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0, "failed opening socket file descriptor\n");

	int reuseaddropt = 1;
	check (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddropt, sizeof reuseaddropt) < 0, "failed configuring socket REUSEADDR\n");

	struct timeval timeout = { .tv_sec = SOCK_IO_TIMEOUT, .tv_usec = 0 };
	check(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0, "failed configuring socket RCVTIMEO\n");
	check(setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0, "failed configuring socket SNDTIMEO\n");

	ADDR_IN sock_addr = getaddr(ADDRESS, PORT);
	check(bind(sockfd, (ADDR*)&sock_addr, sizeof sock_addr) < 0, "could not datagram socket\b");

	for (;;) {
		struct dns_buffer buf_view = {0};
		struct dns_packet packet   = {0};

		ADDR client_addr = {0};
		socklen_t addrlen = sizeof client_addr;

		check((buf_view.size = recvfrom(sockfd, buf_view.buf, sizeof buf_view.buf, 0, (ADDR*)&client_addr, &addrlen)) < 0, "failed while reading query\n");
		dns_btop(&buf_view, &packet);

		trim_packet(&packet); // this is done because when getting the best ipv4 we use resources which must only depend
				      // on our query response! (see extract_best_ipv4)

		uint32_t addr = resolve(&buf_view, &packet, 0);
		check(addr < 0, "failed to recursively resolve packet\n");

		print_ipv4(addr);
		
		struct dns_header header = {0};
		header.id = packet.header.id;
		header.response = true;
		header.recursion_available = true;
		packet.header = header;
		dns_pwrite_answer(&packet, packet.questions[0]->Name, addr);
		dns_ptob(&packet, &buf_view);
		check(sendto(sockfd, buf_view.buf, buf_view.size, 0, &client_addr, addrlen) < 0, "failed to send client response");
	}

	return EXIT_FAILURE;
}

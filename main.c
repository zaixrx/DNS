#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "dnsutils.h"

#define HTABLE_IMPLEMENTATION
#include "hashtable.h"

#define ADDR_IN6 struct sockaddr_in6
#define ADDR_IN  struct sockaddr_in
#define ADDR     struct sockaddr

#define PORT 12000
#define ADDRESS "0.0.0.0"
#define ROOT_MAX_RETRIES 10
#define _RETRANSMISSION_INTERVAL 2 // seconds

static char root_servers[][INET_ADDRSTRLEN] = {
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

// START_GARBAGE
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

static HashTable hs;
static int sockfd;

ADDR_IN getaddr(const char *saddr, uint16_t port) {
	ADDR_IN addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, saddr, &addr.sin_addr.s_addr);
	return addr;
}

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

void check(bool is_error, const char *err_msg) {
	 if (is_error) {
		 perror(err_msg);
		 exit(EXIT_FAILURE);
	 }
}

ssize_t query_ns(const struct dns_question question, struct IPView ipv) {
	struct dns_packet packet = {0};

	struct dns_header header = {0};
	header.id = 69;
	header.recursion_desired = true;
	header.checking_disabled = true;

	packet.header = header;
	dns_pwrite_question(&packet, question);

	struct dns_buffer buffer = {0};
	dns_ptob(&packet, &buffer);

	ADDR addr = {0};
	switch (ipv.ip_version) {
		case _IPv4: {
			memcpy(&addr, &ipv.ip.ipv4, sizeof ipv.ip.ipv4);
		} break;
		case _IPv6: {
			memcpy(&addr, &ipv.ip.ipv6, sizeof ipv.ip.ipv6);
		} break;
		default: return -1;
	}

	return sendto(sockfd, &buffer.buf, buffer.size, 0, &addr, sizeof addr) < 0;
}

ssize_t recv_ns(struct dns_buffer *b, struct IPView ipv) {
	b->pos = 0;

	char addrstr[INET_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET, &ipv.ip.ipv4, addrstr, sizeof addrstr);

	printf("address is %s\n", addrstr);

	ADDR *addr = (ADDR*)&ipv.ip.ipv4;
	socklen_t addrlen = sizeof ipv.ip.ipv4;
	// do proper timeouts(intially of course) and retries
	// the address you are providing is surely wrong fix it
	return b->size = recvfrom(sockfd, b->buf, sizeof b->buf, 0, addr, &addrlen);
}

struct IPView extract_best_ipv4(struct dns_packet packet) {
	int i = 0;
	struct IPView ipv = {0};
	struct dns_record *rr = NULL;
	while (i < packet.c_resources) {
		rr = packet.resources[i];

		if (rr->Type == RT_A) {
			ipv.ip_version = _IPv4;

			ipv.ip.ipv4 = (ADDR_IN){0};
			ipv.ip.ipv4.sin_family = AF_INET;
			ipv.ip.ipv4.sin_port   = ntohs(53);
			ipv.ip.ipv4.sin_addr.s_addr = rr->RD.A.IPv4;

			break;
		} /* else if (rr->Type == RT_AAAA) {
			ipv.ip_version = _IPv6;
			ipv.ip.ipv6 = (ADDR_IN6){
				.sin6_family = AF_INET,
				.sin6_port = ntohs(PORT),
				.sin6_addr.= rr->RD.AAAA.IPv6,
			}
		}*/
		i++;
	}

	check(rr == NULL, "sorry champ no ipv4 resource for you <:( \n");
	
	return ipv;
}

int main(void) {
	entry_presentation();

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		fprintf(stderr, "could not initialize socket\n");
		return EXIT_FAILURE;
	}

	int reuseaddropt = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddropt, sizeof reuseaddropt) < 0) {
		fprintf(stderr, "could not set socket option REUSE ADDRESS\n");
		return EXIT_FAILURE;
	}

	ADDR_IN sock_addr = getaddr(ADDRESS, PORT);
	if (bind(sockfd, (ADDR*)&sock_addr, sizeof sock_addr) < 0) {
		fprintf(stderr, "could not bind socket %d", errno);
		return EXIT_FAILURE;
	}

	char hello[] = "hello\r\n";
	ADDR_IN test_addr = getaddr("127.0.0.1", 8080);
	if (sendto(sockfd, hello, sizeof hello, 0, (ADDR*)&test_addr, sizeof test_addr) < 0) {
		fprintf(stderr, "failed to send test message, errno: %d\n", errno);
		return EXIT_FAILURE;
	};

	printf("successfully bound socket to %s:%d\n", ADDRESS, PORT);

	struct dns_packet packet;
	for (;;) {
		struct dns_buffer buf_view = {0};

		printf("Waiting for stub resovler\n");
		if ((buf_view.size = recv(sockfd, buf_view.buf, sizeof buf_view.buf, 0)) < 0) {
			fprintf(stderr, "could not read from buffer\n");
			continue;
		}
		printf("Got a message from the stub resovler\n");

		int tries = 0;
		for (tries = 0; tries < ROOT_MAX_RETRIES; ++tries) {
			if (tries > 0) sleep(_RETRANSMISSION_INTERVAL);
			
			srand(time(NULL));
			ADDR_IN addr = getaddr(root_servers[rand() % 13], 53);
			socklen_t addrlen = sizeof addr;
			if ((sendto(sockfd, buf_view.buf, buf_view.size, 0, (ADDR*)&addr, addrlen) < 0)) {
				fprintf(stderr, "Failed to query root server %d\n", errno);
				continue;
			}

			memset(&buf_view, 0, sizeof buf_view);
			buf_view.size = recvfrom(sockfd, buf_view.buf, sizeof buf_view.buf, 0, (ADDR*)&addr, &addrlen);
			check(buf_view.size < 0,"failed to read response from root server, retrying...\n");
			dns_btop(&buf_view, &packet);
			dns_pprint(packet);
	
			struct IPView ipv = extract_best_ipv4(packet);
			check(query_ns((struct dns_question) { .Name = "google.com", .Class = 1, .Type = 1 }, ipv) == -1, "you \
					have got bamboozeld mine frienda balls\n");
			check(recv_ns(&buf_view, ipv) == -1, "bad luck! could not query TLD\n");
			dns_btop(&buf_view, &packet);
			dns_pprint(packet);

			ipv = extract_best_ipv4(packet);
			check(query_ns((struct dns_question) { .Name = "google.com", .Class = 1, .Type = 1 }, ipv) == -1, "you \
					have got bamboozeld mine frienda balls\n");
			check(recv_ns(&buf_view, ipv) == -1, "bad luck! could not query TLD\n");
			dns_btop(&buf_view, &packet);
			dns_pprint(packet);

			ipv = extract_best_ipv4(packet);
			check(query_ns((struct dns_question) { .Name = "google.com", .Class = 1, .Type = 1 }, ipv) == -1, "you \
					have got bamboozeld mine frienda balls\n");
			check(recv_ns(&buf_view, ipv) == -1, "bad luck! could not query TLD\n");
			dns_btop(&buf_view, &packet);
			dns_pprint(packet);

			if (packet.answers > 0) {
				char ipstr[INET_ADDRSTRLEN] = {0};
				inet_ntop(AF_INET, &packet.answers[0]->RD.A.IPv4, ipstr, sizeof ipstr);
				printf("Your IP sir %s\n", ipstr);
			}

			break;
		}

		check(tries == ROOT_MAX_RETRIES, "Exceeded retry limit, exiting...");
	}

	return EXIT_FAILURE;
}

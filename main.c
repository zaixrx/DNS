#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <threads.h>
#include <time.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dnsutils.h"

#define HTABLE_IMPLEMENTATION
#include "hashtable.h"

#define ADDR_IN struct sockaddr_in
#define ADDR    struct sockaddr

#define PORT 12000
#define ADDRESS "0.0.0.0"
#define ROOT_MAX_RETRIES 10

/*
recursive resolver server:
1) lookup cache with TTL (Kinda Done)
2) query root server
3) query TLD server from root response(NS record)
4) query the authoritative server with respect to the domain your looking for to get the DNS record(A/AAAA/MX/CNAME) with UDP/IP
*/

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

static HashTable hs = {0};

ADDR_IN getaddr(const char *saddr, uint16_t port) {
	ADDR_IN addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, saddr, &addr.sin_addr.s_addr);
	return addr;
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

int main(void) {
	entry_presentation();

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
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

		int tries;
		for (tries = 0; tries < ROOT_MAX_RETRIES; tries++) {
			sleep(1);

			srand(time(NULL)); // seed rand
			ADDR_IN addr = getaddr(root_servers[rand() % 13], 53);
			socklen_t addrlen = sizeof addr;
			if ((sendto(sockfd, buf_view.buf, buf_view.size, 0, (ADDR*)&addr, addrlen) < 0)) {
				fprintf(stderr, "Failed to query root server %d\n", errno);
				continue;
			}
			printf("Queried root server\nWaiting for response from root server\n");

			memset(&buf_view, 0, sizeof buf_view);
			buf_view.size = recvfrom(sockfd, buf_view.buf, sizeof buf_view.buf, 0, (ADDR*)&addr, &addrlen);
			if (buf_view.size < 0) {
				fprintf(stderr, "failed to read response from root server, retrying...\n");
				continue;
			}
			printf("Got response from root server\n");

			printf("Piping response content to ./root_response.txt\n");
			write_file("./metadata/root_response.txt", &buf_view);

			dns_btop(&buf_view, &packet);
			dns_pprint(packet);

			break;
		}

		if (tries == ROOT_MAX_RETRIES) {
			fprintf(stderr, "Exceeded retry limit, exiting...");
			return EXIT_FAILURE;
		}

	}

	return EXIT_FAILURE;
}

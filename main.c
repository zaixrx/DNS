#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "dnsutils.h"

#define DNS_IPV4 "8.8.8.8"
#define DNS_PORT 53

int read_file(const char *path, char *buf) {
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "couldn't open file %s\n", path);
		return (EXIT_FAILURE);
	}

	size_t size = 0;
	if ((size = read(fd, buf, BUFF_SIZE)) < 0) {
		fprintf(stderr, "couldn't read from opened file %s\n", path);
		close(fd);
		return (EXIT_FAILURE);
	}

	close(fd);
	return size;
}

void setup_address(struct sockaddr_in *addr, const char *ipv4, uint16_t port) {
	bzero(addr, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
	addr->sin_port = htons(DNS_PORT);
	inet_pton(AF_INET, DNS_IPV4, &addr->sin_addr.s_addr);
}

int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "usage: %s <header>\n", argv[0]);
		return EXIT_FAILURE;
	}

	int                sockfd;
	struct sockaddr_in addr;
	struct dns_buffer *dns_qbuf, *dns_rbuf;
	struct dns_packet *dns_qp  , *dns_rp;

	dns_qp = dns_new_packet();
	dns_pwrite_question(dns_qp, "google.com");
	dns_ptob(dns_qp, dns_qbuf);

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	setup_address(&addr, DNS_IPV4, DNS_PORT);
	sendto(sockfd, dns_qbuf->buf, dns_qbuf->size, 0, (struct sockaddr*)&addr, sizeof addr);
	printf("sent dns query!\n");
	dns_rbuf->size = recvfrom(sockfd, dns_rbuf->buf, sizeof(dns_rbuf->buf), 0, NULL, NULL);
	printf("received dns response!\n");
	close(sockfd);

	dns_btop(dns_rbuf, dns_rp);
	dns_pprint(*dns_rp);

	free_dns_packet(dns_qp);
	free_dns_packet(dns_rp);

	return EXIT_SUCCESS;
}

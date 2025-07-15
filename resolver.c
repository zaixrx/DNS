#include <stdlib.h>
#include <stdio.h>
#include "dnsutils.h"

int read_file(const char *path, char *buf, size_t buf_size) {
	FILE *stream = fopen(path, "r");
	if (!stream) return -1;

	int read = fread(buf, buf_size, 1, stream);

	fclose(stream);

	return read;
}

int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "usage: %s <file_path>\n", argv[0]);
		return EXIT_FAILURE;
	}

	struct dns_buffer b = {0};
	if ((b.size = read_file(argv[1], b.buf, sizeof b.buf)) < 0) {
		fprintf(stderr, "failed to read file %s\n", argv[1]);
		return EXIT_FAILURE;
	}

	struct dns_packet p = {0};
		dns_btop(&b, &p);
		dns_pprint(p);
	dns_free_packet(&p);

	return EXIT_SUCCESS;
}

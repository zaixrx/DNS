#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "dnsutils.h"

int read_file(const char *path, struct dns_buffer *p) {
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "couldn't open file %s\n", path);
		return (EXIT_FAILURE);
	}

	if ((p->size = read(fd, p->buf, BUFF_SIZE)) < 0) {
		fprintf(stderr, "couldn't read from opened file %s\n", path);
		close(fd);
		return (EXIT_FAILURE);
	}

	close(fd);
	return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "usage: %s <header>\n", argv[0]);
		return EXIT_FAILURE;
	}

	struct dns_buffer buff = {0};
	if (read_file(argv[1], &buff) == EXIT_FAILURE) {
		fprintf(stderr, "BRO I COULDN'T EVEN READ THE FUCKING FILE\n");
		return EXIT_FAILURE;
	}

	struct dns_packet pack = {0}; 
	if (create_dns_packet(&buff, &pack) == EXIT_FAILURE) {
		fprintf(stderr, "FUCK YOU, AND YOUR SHITTY PACKET!\n");
		return EXIT_FAILURE;
	}

	int i = 0;

	print_header(pack.header);
	while (i < pack.c_questions)
		print_question(*pack.questions[i++]);
	i = 0;
	while (i < pack.c_answers)
		print_record(*(struct A_record*)pack.answers[i++]);

	free_dns_packet(&pack);

	return EXIT_SUCCESS;
}

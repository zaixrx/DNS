CC=cc
CFLAGS=-I/usr/local/include/cjson -L/usr/local/lib/libcjson -lcjson -g -Wall -Wextra

main: main.c sb.c dnsutils.c
	$(CC) $(CFLAGS) -o main $^

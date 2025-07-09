CC=cc
CFLAGS=-I/usr/local/include/cjson -L/usr/local/lib/libcjson -lcjson -g

main: main.c dnsutils.c
	$(CC) $(CFLAGS) -o main $^

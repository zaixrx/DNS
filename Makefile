CC=cc
CFLAGS=-Ilib/ -Llib/ -lcjson -g

main: main.c dnsutils.c
	$(CC) -o main.bin $^ $(CFLAGS)

resolve: resolver.c dnsutils.c
	$(CC) -o resolve.bin $^ $(CFLAGS)

CC=cc
CFLAGS=-Ilib/ -g

main: main.c dnsutils.c ./lib/cJSON.o
	$(CC) $(CFLAGS) -o main.bin $^

resolve: resolver.c dnsutils.c ./lib/cJSON.o
	$(CC) $(CFLAGS) -o resolve.bin $^

./lib/cJSON.o: ./lib/cJSON.c
	$(CC) -c ./lib/cJSON.c -o ./lib/cJSON.o

CC=cc
CFLAGS=-Ilib/ -g

main: main.c dnsutils.c ./lib/cJSON.o
	$(CC) $(CFLAGS) -o main $^

resolve: resolver.c dnsutils.c ./lib/cJSON.o
	$(CC) $(CFLAGS) -o resolve $^

./lib/cJSON.o: ./lib/cJSON.c
	$(CC) -c ./lib/cJSON.c -o ./lib/cJSON.o

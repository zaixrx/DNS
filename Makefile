CC=cc
CFLAGS=-I./

main: main.c sb.c
	$(CC) $(CFLAGS) -o main $^

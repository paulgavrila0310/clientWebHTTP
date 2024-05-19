# Gavrila Paul-Alexandru
# PCOM - Tema 4 - Mai 2024

CC = gcc
CFLAGS = -Wall -I.

client: client.o requests.o helpers.o buffer.o parson.o
	$(CC) $(CFLAGS) -o client client.o requests.o helpers.o buffer.o parson.o

client.o: client.c
	$(CC) $(CFLAGS) -c client.c

requests.o: requests.c
	$(CC) $(CFLAGS) -c requests.c

helpers.o: helpers.c
	$(CC) $(CFLAGS) -c helpers.c

buffer.o: buffer.c
	$(CC) $(CFLAGS) -c buffer.c

parson.o: parson.c
	$(CC) $(CFLAGS) -c parson.c

run: client
	./client

clean:
	rm -f *.o client

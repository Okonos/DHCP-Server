CC=gcc
CFLAGS=-Wall -I.
DEPS = dhcp.h
OBJ = dhcp.c server.o

LIBS=-lnet

%.o: %.c  # $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

server: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f *.o

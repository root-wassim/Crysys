CC=gcc
CFLAGS=-Wall -Wextra -O3 -I.

all: crysys_cli

crysys_cli:
	$(CC) $(CFLAGS) main.c core/*.c "classic encryption"/*.c "modern encryption"/*.c hash/*.c -o crysys_cli -lm

clean:
	rm -f crysys_cli

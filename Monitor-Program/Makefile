CC = gcc
CFLAGS = -Wall -g
LDL = -ldl

PROGS = inject.so

all: $(PROGS)

inject.so: inject.c
	$(CC) -o $@ -shared -fPIC $< $(LDL)

clean:
	rm -f ~* $(PROGS)



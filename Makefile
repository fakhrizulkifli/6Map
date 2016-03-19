CC = gcc
CFLAGS = -g -Wall -Wextra -pedantic
LDFLAGS =
LIBS =
INCS = -I. -I./include
INSTALL = install
PREFIX = /usr/local/
PROG = 6map
SRCS = $(wildcard src/*.c)
OBJS = $(patsubst %.c, %.o, $(SRCS))
SUBDIRS = all install clean
DOC = doc/6map.8
MAN = /usr/man/man8/

all: $(OBJS)
	$(CC) $(CFLAGS) -o bin/$(PROG) $(OBJS) $(INCS) $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< $(LIBS) $(INCS) -o $@

install: $(PROG)
	mv $(PROG) $(PREFIX)/bin/
	gzip $(DOC); cp $(DOC).gz $(MAN)

.PHONY: $(SUBDIRS)

clean:
	rm -f src/*.o bin/$(PROG)

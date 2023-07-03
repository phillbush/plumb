PROG = plumb
OBJS = ${PROG:=.o}
SRCS = ${OBJS:.o=.c}
MAN  = ${PROG:=.1}

PREFIX ?= /usr/local
MANPREFIX ?= ${PREFIX}/share/man

DEFS = -D_POSIX_C_SOURCE=200809L -DGNU_SOURCE -D_BSD_SOURCE
LIBS = -L/usr/local/lib -lmagic
INCS = -I/usr/local/include

bindir = ${DESTDIR}${PREFIX}/bin
mandir = ${DESTDIR}${MANPREFIX}/man1

all: ${PROG}

${PROG}: ${OBJS}
	${CC} -o $@ ${OBJS} ${LIBS} ${LDFLAGS}

.c.o:
	${CC} -std=c99 -pedantic ${DEFS} ${INCS} ${CFLAGS} ${CPPFLAGS} -o $@ -c $<

README: ${MAN}
	mandoc -I os=UNIX -T ascii ${MAN} | col -b | expand -t 8 >README

tags: ${SRCS}
	ctags ${SRCS}

lint: ${SRCS}
	-mandoc -T lint -W warning ${MAN}
	-clang-tidy ${SRCS} -- -std=c99 ${DEFS} ${INCS} ${CPPFLAGS}

clean:
	rm -f ${OBJS} ${PROG} ${PROG:=.core} tags

install: all
	mkdir -p ${bindir}
	mkdir -p ${mandir}
	install -m 755 ${PROG} ${bindir}/${PROG}
	install -m 644 ${MAN} ${mandir}/${MAN}

uninstall:
	-rm ${bindir}/${PROG}
	-rm ${mandir}/${MAN}

.PHONY: all tags clean install uninstall lint

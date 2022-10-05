PROG = plumb
OBJS = plumb.o
SRCS = plumb.c

PREFIX ?= /usr/local
MANPREFIX ?= ${PREFIX}/share/man
LOCALINC ?= /usr/local/include
LOCALLIB ?= /usr/local/lib

# includes and libs
INCS = -I${LOCALINC}
LIBS = -L${LOCALLIB} -lmagic

all: ${PROG}

${PROG}: ${OBJS}
	${CC} -o $@ ${OBJS} ${LIBS} ${LDFLAGS}

.c.o:
	${CC} ${INCS} ${CFLAGS} ${CPPFLAGS} -c $<

README: plumb.1
	man -l plumb.1 | sed 's/.//g' >README

tags: ${SRCS}
	ctags ${SRCS}

clean:
	rm -f ${OBJS} ${PROG} ${PROG:=.core} tags

install: all
	install -d ${DESTDIR}${PREFIX}/bin
	#install -d ${DESTDIR}${MANPREFIX}/man1
	install -m 755 ${PROG} ${DESTDIR}${PREFIX}/bin/${PROG}
	#install -m 644 ${PROG}.1 ${DESTDIR}${MANPREFIX}/man1/${PROG}.1

uninstall:
	rm ${DESTDIR}${PREFIX}/bin/${PROG}
	#rm ${DESTDIR}${MANPREFIX}/man1/${PROG}.1

.PHONY: all tags clean install uninstall

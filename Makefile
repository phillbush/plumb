PROG = plumb
OBJS = ${PROG:=.o}
SRCS = ${OBJS:.o=.c}
MANS = ${PROG:=.1}

PREFIX = /usr/local
MANPREFIX = ${PREFIX}/share/man

LIBS = -lmagic

all: ${PROG} README

${PROG}: ${OBJS}
	${CC} -L/usr/local/lib ${LIBS} ${LDFLAGS} -o $@ ${OBJS}

.c.o:
	${CC} -I/usr/local/include ${CFLAGS} ${CPPFLAGS} -c $<

README: ${MANS}
	man -l ${MANS} | sed 's/.//g' >README

tags: ${SRCS}
	ctags ${SRCS}

clean:
	rm -f ${OBJS} ${PROG} ${PROG:=.core} tags

install: all
	install -d ${DESTDIR}${PREFIX}/bin
	install -d ${DESTDIR}${MANPREFIX}/man1
	install -m 755 ${PROG} ${DESTDIR}${PREFIX}/bin/${PROG}
	install -m 644 ${MANS} ${DESTDIR}${MANPREFIX}/man1/${MANS}

uninstall:
	rm ${DESTDIR}${PREFIX}/bin/${PROG}
	rm ${DESTDIR}${MANPREFIX}/man1/${MANS}

.PHONY: all tags clean install uninstall

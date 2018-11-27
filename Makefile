PROG=	findingsd
SRCS=	findingsd.c
CFLAGS+= -I/usr/local/include -I/usr/local/include/mysql
LDADD+= -lpcap -lcrypto -L/usr/local/lib -lmysqlclient
MAN =

.include <bsd.prog.mk>

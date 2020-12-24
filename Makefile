PROG=	findingsd
SRCS=	findingsd.c
CFLAGS+= -I/usr/local/include `mysql_config --cflags`
LDADD+= -lpcap -lcrypto `mysql_config --libs`
MAN =

.include <bsd.prog.mk>

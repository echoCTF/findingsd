PROG=	findingsd
SRCS=	findingsd.c
CFLAGS+= -I/usr/local/include `mysql_config --cflags`
LDADD+= -lpcap -lcrypto `mysql_config --libs` -L/usr/local/lib -lmemcached
MAN =

.include <bsd.prog.mk>

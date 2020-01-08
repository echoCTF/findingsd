/*
 * Based on spamlogd.c,v 1.27
 * ORIGINAL COPYRIGHTS
 * Copyright (c) 2006 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2006 Berk D. Demir.
 * Copyright (c) 2004-2007 Bob Beck.
 * Copyright (c) 2001 Theo de Raadt.
 * Copyright (c) 2001 Can Erkin Acar.
 * All rights reserved
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* watch pf log for connections, update findings entries. */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/signal.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <net/pfvar.h>
#include <net/if_pflog.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <my_global.h>
#include <mysql.h>

#define MIN_PFLOG_HDRLEN  45
#define PCAPSNAP    512
#define PCAPTIMO    500  /* ms */
#define PCAPOPTZ    1  /* optimize filter */
#define PCAPFSIZ    512  /* pcap filter string size */

#define FINDINGSD_USER    "_findingsd"


int debug = 1;

u_int8_t  flag_debug = 0;
char      *pflogif = "pflog0";
char      errbuf[PCAP_ERRBUF_SIZE];
pcap_t    *hpcap = NULL;
struct syslog_data   sdata  = SYSLOG_DATA_INIT;
MYSQL *con;
static MYSQL_STMT *insertStmt;
extern char    *__progname;

void  logmsg(int , const char *, ...);
void  sighandler_close(int);
int   init_pcap(void);
void  logpkt_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
int   dbupdate(char *, char *, u_int16_t, char *);
__dead void  usage(void);

void
logmsg(int pri, const char *msg, ...)
{
  va_list  ap;
  va_start(ap, msg);

  if (flag_debug) {
    vfprintf(stderr, msg, ap);
    fprintf(stderr, "\n");
  } else {
    vsyslog_r(pri, &sdata, msg, ap);
  }

  va_end(ap);
}

void
sighandler_close(int signal)
{
  if (hpcap != NULL)
    pcap_breakloop(hpcap);  /* sighdlr safe */
}

int
init_pcap(void)
{
  struct bpf_program  bpfp;
  char  filter[PCAPFSIZ] = "ip";

  if ((hpcap = pcap_open_live(pflogif, PCAPSNAP, 1, PCAPTIMO,
      errbuf)) == NULL) {
        logmsg(LOG_ERR, "Failed to initialize: %s", errbuf);
        return (-1);
  }

  if (pcap_datalink(hpcap) != DLT_PFLOG) {
    logmsg(LOG_ERR, "Invalid datalink type");
    pcap_close(hpcap);
    hpcap = NULL;
    return (-1);
  }

  if (pcap_compile(hpcap, &bpfp, filter, PCAPOPTZ, 0) == -1 ||
      pcap_setfilter(hpcap, &bpfp) == -1) {
        logmsg(LOG_ERR, "%s", pcap_geterr(hpcap));
        return (-1);
  }

  pcap_freecode(&bpfp);

  if (ioctl(pcap_fileno(hpcap), BIOCLOCK) < 0) {
    logmsg(LOG_ERR, "BIOCLOCK: %s", strerror(errno));
    return (-1);
  }

  return (0);
}

void
logpkt_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
  sa_family_t        af;
  u_int8_t           hdrlen;
  u_int32_t          caplen = h->caplen;
  const struct ip    *ip = NULL;
  const struct pfloghdr  *hdr;
  struct protoent *pp;
  char straddr_src[40] = { '\0' }, straddr_dst[40] = { '\0' };
  u_int16_t dport=0;
  time_t _tm =time(NULL );
  struct tm * curtime = localtime ( &_tm );
  char *timestring=asctime(curtime);
  timestring[strlen(timestring) - 1] = 0;
  hdr = (const struct pfloghdr *)sp;
  if (hdr->length < MIN_PFLOG_HDRLEN) {
    logmsg(LOG_WARNING, "invalid pflog header length (%u/%u). "
      "packet dropped.", hdr->length, MIN_PFLOG_HDRLEN);
    return;
  }
  hdrlen = BPF_WORDALIGN(hdr->length);

  if (caplen < hdrlen) {
    logmsg(LOG_WARNING, "pflog header larger than caplen (%u/%u). "
      "packet dropped.", hdrlen, caplen);
    return;
  }

  af = hdr->af;
  if (af == AF_INET) {
    ip = (const struct ip *)(sp + hdrlen);
    inet_ntop(af, &ip->ip_src, straddr_src,sizeof(straddr_src));
    inet_ntop(af, &ip->ip_dst, straddr_dst,sizeof(straddr_dst));
    if (ip->ip_p == IPPROTO_UDP) {
        dport = ntohs(hdr->dport);
        pp=getprotobynumber(IPPROTO_UDP);
    } else if (ip->ip_p == IPPROTO_ICMP) {
        dport = 0;
        pp=getprotobynumber(IPPROTO_ICMP);
    } else if (ip->ip_p == IPPROTO_TCP) {
        dport = ntohs(hdr->dport);
        pp=getprotobynumber(IPPROTO_TCP);
    }
  }

  if (straddr_dst[0] != '\0' && straddr_src[0] != '\0') {
    logmsg(LOG_DEBUG,"[%s] SRC: %s => DST: => %s:%d, PROTO: %s",timestring,straddr_src,straddr_dst, dport, pp->p_name);
    if (mysql_ping(con)) {
      logmsg(LOG_DEBUG,"Ping error: %s", mysql_error(con));
    } else {
      dbupdate(straddr_src,straddr_dst, dport, pp->p_name);
    }
  }
}

int
dbupdate(char *ip_src, char *ip_dst, u_int16_t port_dst, char *p_name)
{
  static MYSQL_BIND insertBinds[4];
  static unsigned long srcLen=0,dstLen=0,p_nameLen=0;
  static int port[1]={0};
  static char src[15]={0},dst[15]={0},proto[6]={0};
  const char insertQuery[]=
    "INSERT INTO findingsd ( srcip, dstip,dstport, proto) VALUES (INET_ATON(?),INET_ATON(?),?,?)";


  if (!insertStmt) {
    memset(insertBinds, 0, sizeof(insertBinds));

    insertBinds[0].buffer_type = MYSQL_TYPE_STRING;
    insertBinds[0].buffer =(char *)src;
    insertBinds[0].buffer_length = sizeof(src);
    insertBinds[0].length = &srcLen;

    insertBinds[1].buffer_type = MYSQL_TYPE_STRING;
    insertBinds[1].buffer = dst;
    insertBinds[1].buffer_length = sizeof(dst);
    insertBinds[1].length = &dstLen;

    insertBinds[2].buffer_type = MYSQL_TYPE_LONG;
    insertBinds[2].buffer = port;
    insertBinds[2].buffer_length = sizeof(port);
    insertBinds[2].length = 0;

    insertBinds[3].buffer_type = MYSQL_TYPE_STRING;
    insertBinds[3].buffer = proto;
    insertBinds[3].buffer_length = sizeof(proto);
    insertBinds[3].length = &p_nameLen;

    insertStmt = mysql_stmt_init(con);
    if (!insertStmt){
      insertStmt=NULL;
      return -1;
    }
    if (mysql_stmt_prepare(insertStmt, insertQuery, sizeof(insertQuery)) > 0){
      logmsg(LOG_ERR,"failed mysql_stmt_prepare");
      mysql_stmt_close(insertStmt);
      insertStmt=NULL;
      return -1;
    }

    if (mysql_stmt_bind_param(insertStmt, insertBinds) > 0){
      logmsg(LOG_ERR,"failed mysql_stmt_bind_param");
      mysql_stmt_close(insertStmt);
      insertStmt=NULL;
      return -1;
    }
  }

  memset(src, 0, sizeof(src));
  memset(dst, 0, sizeof(dst));
  memset(proto, 0, sizeof(proto));
  memset(port, 0, sizeof(port));


  strncpy(dst, ip_dst, sizeof(dst));
  strncpy(src, ip_src, sizeof(src));
  strncpy(proto, p_name, sizeof(proto));
  port[0]=port_dst;

  dstLen=strlen(dst);
  srcLen=strlen(src);
  p_nameLen=strlen(proto);
  if (mysql_stmt_execute(insertStmt))
  {
    fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(insertStmt));
    return -1;
  }

  return 0;
}

void
usage(void)
{
  fprintf(stderr,
      "usage: %s [-D] [-l pflog_interface] [-u dbuser] [-p dbpassword] [-h dbhost] [-n dbname] [-t wait_timeout]\n",
      __progname);
  exit(1);
}

int
main(int argc, char **argv)
{
  int     ch;
  struct passwd  *pw;
  my_bool reconnect=1;
  int wait_timeout=31536000;
  char wait_timeoutq[512];
  char *dbuser="",*dbpass="",*dbname="echoctf",*dbhost="localhost";
  pcap_handler   phandler = logpkt_handler;

  while ((ch = getopt(argc, argv, "Dl:u:p:h:n:t:")) != -1) {
    switch (ch) {
      case 'D':
        flag_debug = 1;
        break;
      case 'l':
        pflogif = optarg;
        break;
      case 'u':
        dbuser = optarg;
        break;
      case 'p':
        dbpass = optarg;
        break;
      case 'h':
        dbhost = optarg;
        break;
      case 'n':
        dbname = optarg;
        break;
      case 't':
        wait_timeout = atoi(optarg);
        break;
      default:
        usage();
    }
  }
  if (geteuid())
    errx(1, "need root privileges");

  insertStmt=NULL;


  signal(SIGINT , sighandler_close);
  signal(SIGQUIT, sighandler_close);
  signal(SIGTERM, sighandler_close);

  logmsg(LOG_DEBUG, "Listening on %s", pflogif);
  con = mysql_init(NULL);
  if (con == NULL)
      errx(1, "%s",mysql_error(con));

  if (mysql_real_connect(con, dbhost,dbuser,dbpass, dbname, 0, NULL, CLIENT_REMEMBER_OPTIONS) == NULL)
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      mysql_close(con);
      exit(1);
  }
  if (mysql_options(con, MYSQL_OPT_RECONNECT,&reconnect)) {
      printf("MySQL Options failed: %s\n", mysql_error(con));
  }


  snprintf(wait_timeoutq, sizeof(wait_timeoutq),"SET wait_timeout = %d", wait_timeout);
  if(mysql_query (con,wait_timeoutq)!=0)
  {
    fprintf(stderr, "Setting wait_timeout failed with error: %s\n", mysql_error(con));
    mysql_close(con);
    exit(1);
  }

  if (init_pcap() == -1)
    err(1, "couldn't initialize pcap");

  /* privdrop */
  if ((pw = getpwnam(FINDINGSD_USER)) == NULL)
    errx(1, "no such user %s", FINDINGSD_USER);

  if (setgroups(1, &pw->pw_gid) ||
      setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
      setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid)) {
    err(1, "failed to drop privs");
  }

  if (!flag_debug) {
    if (daemon(0, 0) == -1)
      err(1, "daemon");

    tzset();
    openlog_r("findingsd", LOG_PID | LOG_NDELAY, LOG_DAEMON, &sdata);
  }

  pcap_loop(hpcap, -1, phandler, NULL);

  logmsg(LOG_NOTICE, "exiting");
  if (!flag_debug)
    closelog_r(&sdata);

  mysql_close(con);

  exit(0);
}

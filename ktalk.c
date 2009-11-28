/*
Copyright © 1999 James Kretchmar

All rights reserved.

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted, provided that
the above copyright notice appear in all copies and that both that copyright
notice and this permission notice appear in supporting documentation, and that
the name of James Kretchmar not be used in advertising or publicity pertaining
to distribution of the software without specific, written prior permission.

JAMES KRETCHMAR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT
SHALL JAMES KRETCHMAR BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <krb5.h>
#include <errno.h>
#include <zephyr/zephyr.h>
#include <signal.h>
#include <curses.h>
#include <sys/wait.h>

typedef enum { MODE_SERVER, MODE_CLIENT } ktalk_mode;

int server_open(const char *user, struct sockaddr_in *faddr, char *execstr);
int client_open(const char *user, const char *host, unsigned short port, struct sockaddr_in *faddr);

int netread(int fd, char *ptr, int nbytes);
int netwrite(int fd, char *ptr, int nbytes);
int netreadlen(int fd);
int netreaddata(int fd, char **ptr);
void netwritedata(int fd, char *ptr, int nbytes);
void send_connect_message(const char *recip, int port, char *estr);
void kill_and_die(int);
void window_change(int);

void auth_con_setup(krb5_context context, krb5_auth_context *auth_context, krb5_address *local_address, krb5_address *foreign_address);
void debug_remoteseq(krb5_context context, krb5_auth_context auth_context, const char *whence);
void debug_localseq(krb5_context context, krb5_auth_context auth_context, const char *whence);
void sockaddr_to_krb5_address(krb5_address *k5, struct sockaddr *sock);
void fail(long err, const char *context);
void bye(const char *message);

int sockfd, curs_start, use_curses, debug_flag;
int need_resize = 0;

inline void debug(const char *format, ...) {
  va_list ap;
  char fmtbuf[1024];

  va_start(ap, format);
  if (debug_flag) {
    snprintf(fmtbuf, sizeof(fmtbuf), "DEBUG: %s\n", format);
    vfprintf(stderr, fmtbuf, ap);
  }
  va_end(ap);
}

void usage(const char *whoami) {
  fprintf(stderr, "usage: %s [-e messager] <user>\n       %s <user> <host> <port>\n", whoami, whoami);
  exit(1);
}
 
int main(int argc, char **argv) {
  ktalk_mode mode;
  int ret, writebufflen;
  char *execstr = NULL;
  krb5_context context;
  krb5_ccache ccache;
  char *my_principal_string;
  krb5_address local_address, foreign_address;
  struct sockaddr_in faddr, laddr;
  size_t laddrlen;
  WINDOW *sendwin = NULL, *receivewin = NULL, *sepwin = NULL;
  fd_set fdset;
  struct sigaction sigact;
  char writebuff[1024], startupmsg[2048];
  krb5_principal my_principal;
  krb5_auth_context auth_context;
  int opt;
  extern char *optarg;
  extern int optind;

  use_curses = 1;
  debug_flag = 0;
  curs_start=0;
  strcpy(startupmsg, "");

  while((opt = getopt(argc, argv, "dce:")) != -1) {
    switch(opt) {
    case 'e':
      execstr = optarg;
      break;
    case 'd':
      debug_flag = !debug_flag;
      break;
    case 'c':
      use_curses = !use_curses;
      break;
    default:
      usage(argv[0]);
    }
  }

  switch(argc - optind) {
  case 1:
    mode = MODE_SERVER;
    break;
  case 3:
    mode = MODE_CLIENT;
    break;
  default:
    usage(argv[0]);
  }

  sigemptyset(&sigact.sa_mask);
  sigact.sa_flags = 0;
  sigact.sa_handler = kill_and_die;
  sigaction(SIGINT, &sigact, NULL);
  sigact.sa_handler = window_change;
  sigaction(SIGWINCH, &sigact, NULL);

  /* kerberos set up for both client and server */
  putenv("KRB5_KTNAME=/dev/null"); /* kerberos V can kiss my pasty white ass */
  ret = krb5_init_context(&context);
  if (ret)
    fail(ret, "krb5_init_context");
  ret = krb5_cc_default(context, &ccache);
  if (ret)
    fail(ret, "krb5_cc_default");
  ret = krb5_cc_get_principal(context, ccache, &my_principal);
  if (ret)
    fail(ret, "krb5_cc_get_principal");
  ret = krb5_unparse_name(context, my_principal, &my_principal_string);
  if (ret)
    fail(ret, "krb5_unparse_name");
  debug("you are %s", my_principal_string);

  if (mode == MODE_SERVER) {
    sockfd = server_open(argv[optind], &faddr, execstr);
  } else if (mode == MODE_CLIENT) {
    sockfd = client_open(argv[optind], argv[optind + 1], atoi(argv[optind + 2]), &faddr);
  }
  puts("connection established.");

  /* get our local address */
  laddrlen = sizeof(laddr);
  ret = getsockname(sockfd, (struct sockaddr *)&laddr, &laddrlen);
  if (ret != 0)
    perror("getsockname");
  sockaddr_to_krb5_address(&local_address, (struct sockaddr *)&laddr);

  /* get the foreign address */
  sockaddr_to_krb5_address(&foreign_address, (struct sockaddr *)&faddr);

  if (mode == MODE_SERVER) {
    krb5_creds in_creds, *out_creds;
    krb5_ticket *inticket = NULL;
    krb5_data msg;
    krb5_principal clprinc;
    char *fprincipal, *clprincstr;
    
    /* get the krbtgt/REALM@REALM from the cache into out_creds */
    memset(&in_creds, 0, sizeof(in_creds));
    ret = krb5_cc_get_principal(context, ccache, &in_creds.client);
    if (ret)
      fail(ret, "krb5_cc_get_principal");

    ret = krb5_build_principal_ext(context, &in_creds.server,
				   krb5_princ_realm(context, in_creds.client)->length,
				   krb5_princ_realm(context, in_creds.client)->data,
				   6, "krbtgt",
				   krb5_princ_realm(context, in_creds.client)->length,
				   krb5_princ_realm(context, in_creds.client)->data,
				   0);
    if (ret)
      fail(ret, "krb5_build_principal_ext");

    ret = krb5_get_credentials(context, KRB5_GC_CACHED, ccache, 
			       &in_creds, &out_creds);
    if (ret)
      fail(ret, "krb5_get_credentials");

    /* send over the user_user ticket */
    netwritedata(sockfd, out_creds->ticket.data, out_creds->ticket.length);

    /* initialize the auth_context */
    auth_con_setup(context, &auth_context, &local_address, &foreign_address);
    ret = krb5_auth_con_setuseruserkey(context, auth_context, &out_creds->keyblock);
    if (ret)
      fail(ret, "krb5_auth_con_setuseruserkey");

    /* read the mk_req data sent by the client */
    ret = netreaddata(sockfd, &msg.data);
    debug("read message, length was %i", ret);
    if (ret < 0)
      fail(errno, "reading ticket from client");
    msg.length = ret;
    ret = krb5_rd_req(context, &auth_context, &msg, NULL, NULL, NULL, &inticket);
    debug("read message with rd_req, return was %i", ret);
    if (ret)
      fail(ret, "krb5_rd_req");
    free(msg.data);

    ret = krb5_unparse_name(context, inticket->enc_part2->client, &fprincipal);
    if (ret)
      fail(ret, "krb5_unparse_name");
    strcat(startupmsg, "Foreign party authenticates as ");
    strcat(startupmsg, fprincipal);
    strcat(startupmsg, "\n\n");

    /* this is a little wrong, the argv[1] may have @ATHENA.MIT.EDU */ /***** need to fix *****/
    ret = krb5_parse_name(context, argv[optind], &clprinc);
    if (ret)
      fail(ret, "krb5_parse_name");
    ret = krb5_unparse_name(context, clprinc, &clprincstr);
    if (ret)
      fail(ret, "krb5_unparse_name");
    if (strcasecmp(fprincipal, clprincstr)) {
      strcat(startupmsg,"WARNING! This is not the principal you specified on the\n");
      strcat(startupmsg,"command line.  An encrypted session will be established anyway\n");
      strcat(startupmsg,"make sure you really want to talk to this person.\n\n");
    }
    free(fprincipal);
    free(clprincstr);
  } else if (mode == MODE_CLIENT) {
    krb5_data tkt_data, out_ticket;
    krb5_creds *new_creds, creds;
    /* char fprincipal[1024]; */

    auth_con_setup(context, &auth_context, &local_address, &foreign_address);

    /* get the principal */
    /*    i=netreaddata(sockfd, fprincipal);
	  debug("got foreign principal %s over the wire", fprincipal);
    */
    
    /* read the ticket sent by the server */
    ret = netreaddata(sockfd, &tkt_data.data);
    debug("got the ticket, length was %i", ret);
    if (ret < 0)
      fail(errno, "reading ticket from server");
    tkt_data.length = ret;

    memset(&creds, 0, sizeof(creds));
    
    /* parse the foreign principal into creds.server */
    ret = krb5_parse_name(context, argv[optind], &creds.server);
    if (ret)
      fail(ret, "krb5_parse_name");
    /* insert our own principal in creds.client */
    ret = krb5_cc_get_principal(context, ccache, &creds.client);
    if (ret)
      fail(ret, "krb5_cc_get_principal");
    
    /* get user_user ticket */
    creds.second_ticket = tkt_data;

    ret = krb5_get_credentials(context, KRB5_GC_USER_USER, ccache, &creds, &new_creds);
    if (ret)
      fail(ret, "getting user to user credentials");
    debug("Got the user_user ticket!");

    /* do the mk_req and send the ticket to the server */
    ret = krb5_mk_req_extended(context, &auth_context, AP_OPTS_USE_SESSION_KEY|AP_OPTS_MUTUAL_REQUIRED,
			       NULL, new_creds, &out_ticket);
    if (ret)
      fail(ret, "krb5_mk_req_extended");

    netwritedata(sockfd, out_ticket.data, out_ticket.length);
    debug("sent mk req message, return was %i", ret);

    free(tkt_data.data); 
  }

  /* setup screen */
  if (use_curses) {
    initscr();
    cbreak(); noecho();
    intrflush(stdscr,FALSE); keypad(stdscr,TRUE);
    nodelay(stdscr,1);
    clear();
    refresh();
    curs_start=1;
  
    writebufflen=0;

    /* setup send / receive windows and the seperator */
    receivewin = newwin(LINES/2, COLS, 0, 0);
    sepwin = newwin(1, COLS, LINES/2, 0);
    sendwin = newwin(LINES - LINES/2 - 1, COLS, LINES/2 + 1, 0);

    nodelay(sendwin, 1);
    idlok(sendwin, 1);
    scrollok(sendwin, 1);
    idlok(receivewin, 1);
    scrollok(receivewin, 1);

    whline(sepwin, ACS_HLINE, COLS);

    wmove(receivewin, 0, 0);
    wmove(sendwin, 0, 0);

    wstandout(receivewin);
    waddstr(receivewin, startupmsg);
    wstandend(receivewin);
  
    wnoutrefresh(receivewin);
    wnoutrefresh(sendwin);
    wnoutrefresh(sepwin);
    doupdate();
  }


  for (;;) {
    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);
    FD_SET(fileno(stdin), &fdset);
    ret = select(sockfd+1, &fdset, NULL, NULL, NULL);
    if (ret < 0) {
      if (errno == EINTR) {
	if (need_resize && use_curses) {
	  need_resize = 0;

	  endwin();
	  refresh();

	  wresize(receivewin, LINES/2, COLS);

	  mvwin(sepwin, LINES/2, 0);
	  wresize(sepwin, 1, COLS);
	  werase(sepwin);
	  mvwhline(sepwin, 0, 0, ACS_HLINE, COLS);

	  mvwin(sendwin, LINES/2 + 1, 0);
	  wresize(sendwin, LINES - LINES/2 - 1, COLS);

	  werase(receivewin);
	  wmove(receivewin, 0, 0);

	  werase(sendwin);
	  wmove(sendwin, 0, 0);

	  wnoutrefresh(receivewin);
	  wnoutrefresh(sendwin);
	  wnoutrefresh(sepwin);
	}
      } else {
	fail(errno, "waiting for data");
      }
    } else if (FD_ISSET(sockfd, &fdset)) {
      /* decrypt and print the incomming message */
      krb5_data msg, encmsg;
      ret = netreaddata(sockfd, &encmsg.data);
      debug("received message %d bytes", ret);
      if (ret < 0)
	fail(errno, "reading chat data from network");
      encmsg.length = ret;
      debug_remoteseq(context, auth_context, "before");
      ret = krb5_rd_priv(context, auth_context, &encmsg, &msg, NULL);
      debug_remoteseq(context, auth_context, "after");

      if (ret)
	fail(ret, "krb5_rd_priv");
	
      if (use_curses) {
	waddstr(receivewin, msg.data);
	wnoutrefresh(receivewin);
      } else {
	printf("%s",msg.data);
      }
      krb5_free_data_contents(context, &msg);
      free(encmsg.data);
    } else if (FD_ISSET(fileno(stdin), &fdset)) {
      if (!use_curses) {
	/* read from the line */
	if (fgets(writebuff, 1024, stdin) == NULL)
	  fail(errno, "reading from user");
	writebufflen = strlen(writebuff);
      } else if (use_curses) {
	/* read from the sending window */
	int j, x, y;

	while((j = wgetch(sendwin)) != ERR) {
	  if (j == 8 || j == 127) {
	    getyx(sendwin, y, x);
	    if (x > 0) {
	      wmove(sendwin, y, x-1);
	      waddch(sendwin, ' ');
	      wmove(sendwin, y, x-1);
	      wrefresh(sendwin);
	      if (writebufflen)
		writebufflen--;
	      writebuff[writebufflen] = 0;
	    }
	  } else if (j > 32 || j == 10 || j ==13) {
	    writebuff[writebufflen] = j;
	    writebufflen++;
	    waddch(sendwin, j);
	    wnoutrefresh(sendwin);

	    writebuff[writebufflen] = 0;
	  }
	}
      }
      if (writebufflen && (writebuff[writebufflen - 1] == '\n'
			   || writebuff[writebufflen - 1] == '\r')) {
	krb5_data msg, encmsg;

	/* we have a whole line now, send it off */
	msg.data = writebuff;
	msg.length = writebufflen + 1;
	writebufflen = 0;
	debug_localseq(context, auth_context, "before");
	ret = krb5_mk_priv(context, auth_context, &msg, &encmsg, NULL);
	if (ret)
	  fail(ret, "krb5_mk_priv");
	debug_localseq(context, auth_context, "after");
	netwritedata(sockfd, encmsg.data, encmsg.length);
	free(encmsg.data);
      }
    }
    if (use_curses)
      doupdate();
  }

}


int netread(int fd, char *ptr, int nbytes) {
  int nleft, nread;

  nleft = nbytes;
  while (nleft > 0) {
    nread = read(fd, ptr, nleft);
    debug("read returned %d", nread);
    if (nread < 0)
      return nread;
    else if (nread == 0)
      break;
    nleft -= nread;
    ptr += nread;
  }
  return(nbytes - nleft);
}


int netwrite(int fd, char *ptr, int nbytes) {
  int nleft, nwritten;

  nleft = nbytes;
  while (nleft > 0) {
    nwritten=write(fd, ptr, nleft);
    if (nwritten <= 0) return(nwritten);

    nleft -= nwritten;
    ptr += nwritten;
  }
  return(nbytes - nleft);
}


int netreadlen(int fd) {
  char *ptr;
  int ret;
  int off = 0;
  
  ptr = malloc(1024);
  
  do {
    ret = netread(fd, &ptr[off], 1);
    if (ret < 0) {
      free(ptr);
      return -1;
    }
    if (ret == 0)
      return 0;
    if (ptr[off] == '\0')
      break;
    off++;
  } while (off < 1024);
  
  ret=atoi(ptr);
  free(ptr);
  return(ret);
}


void netwritedata(int fd, char *ptr, int nbytes) {
  char len[1024];

  sprintf(len, "%i", nbytes);
  netwrite(fd, len, strlen(len)+1);
  netwrite(fd, ptr, nbytes);
}


int netreaddata(int fd, char **p) {
  int i, ret;
  char *ptr;

  i = netreadlen(fd);
  if (i == 0)
    bye("connection closed");
  if (i < 0 || i > 1024)
    return -1;
  
  ptr = malloc(i);
  ret = netread(fd, ptr, i);
  if (ret <= 0) {
    bye("connection closed");
  }

  *p = ptr;
  
  return i;
}


void send_connect_message(const char *recip, int port, char *execstr) {
  char hostname[NS_MAXDNAME + 1];
  ZNotice_t notice;
  char *list[2];
  char msg[2048];
  char *sender, *foo;
  int ret;

  gethostname(hostname, NS_MAXDNAME);
  if (strcasecmp(&hostname[strlen(hostname) - 8], ".mit.edu") == 0)
    hostname[strlen(hostname) - 8] = '\0';
  
  ZInitialize();

  sender = strdup(ZGetSender());
  foo = strstr(sender, "@ATHENA.MIT.EDU");
  if (foo)
    *foo='\0';

  if (execstr) {
    ret = fork();
    if (ret < 0) {
      fprintf(stderr, "could not fork to send connection message\n");
    } else if (ret > 0) {
	wait3(NULL, WNOHANG, NULL);
	return;
    } else { /* ret == 0; child */
      foo = malloc(10);
      sprintf(foo, "%i", port);
      ret = execlp(execstr, execstr, sender, hostname, foo, NULL);
      if (ret) {
	fprintf(stderr, "could not exec %s to send connection message\n", execstr);
	exit(1);
      }
      /*NOTREACHED*/
    }
  }

  snprintf(msg, 2048,
	   "This user is requesting a krb5 user to user encrypted communication channel.\n"
	  "To open the channel type:\n"
	  "\n   add ktools\n"
	  "   ktalk %s %s %i\n"
	  "\nat the Athena%% prompt.\n",
	  sender, hostname, port);

  free(sender);

  memset(&notice, 0, sizeof(notice));
  notice.z_kind=ACKED; 
  notice.z_class="message";
  notice.z_class_inst="personal";
  notice.z_recipient = (char *)recip;
  notice.z_default_format="Class $class, Instance $instance:\nTo: @bold($recipient) at $time $date\nFrom: @bold{$1 <$sender>}\n\n$2"; 
  notice.z_sender=ZGetSender();
  notice.z_opcode="";
  
  list[0]="Advertise here";
  list[1] = msg;
  
  ZSendList(&notice, list, 2, ZAUTH);
  ZFreeNotice(&notice);
}

void kill_and_die(int sig) {
  bye("exiting due to interrupt");
}

void window_change(int sig) {
  need_resize = 1;
}

void auth_con_setup(krb5_context context, krb5_auth_context *auth_context, krb5_address *local_address, krb5_address *foreign_address) {
  int ret;

  /* initialize the auth_context */
  ret = krb5_auth_con_init(context, auth_context);
  if (ret)
    fail(ret, "krb5_auth-con_init");

  ret = krb5_auth_con_setflags(context, *auth_context, KRB5_AUTH_CONTEXT_DO_SEQUENCE);
  if (ret)
    fail(ret, "krb5_auth_con_setflags");

  ret = krb5_auth_con_setaddrs(context, *auth_context, local_address, foreign_address);
  if (ret)
    fail(ret, "krb5_auth_con_setaddrs");
}

void debug_remoteseq(krb5_context context, krb5_auth_context auth_context, const char *whence) {
  krb5_int32 seqnumber;
  int ret;

  if (debug_flag) {
    ret = krb5_auth_con_getremoteseqnumber(context, auth_context, &seqnumber);
    if (ret)
      fail(ret, "krb5_auth_con_getremoteseqnumber");
    debug("%s remote seq is %i", whence, seqnumber);
  }
}

void debug_localseq(krb5_context context, krb5_auth_context auth_context, const char *whence) {
  krb5_int32 seqnumber;
  int ret;

  if (debug_flag) {
    ret = krb5_auth_con_getlocalseqnumber(context, auth_context, &seqnumber);
    if (ret)
      fail(ret, "krb5_auth_con_getlocalseqnumber");
    debug("%s local seq is %i", whence, seqnumber);
  }
}

void sockaddr_to_krb5_address(krb5_address *k5, struct sockaddr *sock) {
  switch (sock->sa_family) {
  case AF_INET:
    {
      struct sockaddr_in *sin = (struct sockaddr_in *)sock;

      k5->addrtype = ADDRTYPE_INET;
      k5->length = sizeof(sin->sin_addr);
      k5->contents = malloc(k5->length);
      memcpy(k5->contents, &sin->sin_addr, k5->length);
    }
    break;
  default:
    fprintf(stderr, "can't copy address"); /* XXX */
    break;
  }
}

int server_open(const char *user, struct sockaddr_in *faddr, char *execstr) {
  int ret, servsock;
  unsigned short port = 2050;
  struct sockaddr_in laddr;
  size_t faddrlen;
  int fd;

  /* start listening on the first port we can find */
  port = 2050;
  servsock = socket(AF_INET, SOCK_STREAM, 0);
  if (servsock < 0)
    fail(errno, "creating socket");
  
  memset(&laddr, 0, sizeof(laddr));
  laddr.sin_family = AF_INET;
  laddr.sin_addr.s_addr = htonl(INADDR_ANY);
  laddr.sin_port = htons(port);
  
  while ((ret = bind(servsock, (struct sockaddr *)&laddr, sizeof(laddr))) != 0) {
    if (errno == EADDRINUSE) {
      port++;
      laddr.sin_port = htons(port);
    } else {
      fail(errno, "binding address");
    }
  }
  
  ret = listen(servsock, 5);
  if (ret < 0)
    fail(errno, "listening for connection");
  
  send_connect_message(user, port, execstr);
  
  printf("waiting for connection on port %i .... \n", port);
  memset(faddr, 0, sizeof(faddr));
  faddrlen = sizeof(*faddr);
  fd = accept(servsock, (struct sockaddr *)faddr, &faddrlen);
  if (fd < 0)
    fail(errno, "accepting connection");

  close(servsock);

  return fd;
}

int client_open(const char *user, const char *host, unsigned short port, struct sockaddr_in *faddr) {
  int fd, ret;
  extern int h_errno;
  struct hostent *fhent;

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    fail(errno, "creating socket");

  fhent = gethostbyname(host);
  if (!fhent) {
    fprintf(stderr, "%s: %s\n", host, hstrerror(h_errno));
    exit(1);
  }
  memset(faddr, 0, sizeof(faddr));
  memcpy(&faddr->sin_addr, fhent->h_addr, sizeof(struct in_addr));
  faddr->sin_family = AF_INET;
  faddr->sin_port = htons(port);

  ret = connect(fd, (struct sockaddr *)faddr, sizeof(*faddr));
  if (ret != 0)
    fail(errno, "connecting");

  return fd;
}

void fail(long err, const char *context) {
  if (curs_start)
    endwin();
  fprintf(stderr, "%s: %s\n", context, error_message(err));
  exit(1);
}

void bye(const char *message) {
  if (curs_start)
    endwin();
  puts(message);
  exit(0);
}
/*
 * Local Variables:
 * mode:C
 * c-basic-offset:2
 * End:
 */

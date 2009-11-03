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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <krb5.h>
#include <errno.h>
#include <zephyr/zephyr.h>
#include <signal.h>
#include <curses.h>
#include <sys/wait.h>

#define MODE_SERVER 1
#define MODE_CLIENT 2

int netread(int fd, char *ptr, int nbytes);
int netwrite(int fd, char *ptr, int nbytes);
int netreadlen(int fd);
int netreaddata(int fd, char **ptr);
void netwritedata(int fd, char *ptr, int nbytes);
void send_connect_message(char *recip, int port, char *estr);
void netkill(int fd);
void leave();
void kill_and_die();

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

int newsockfd, curs_start, connest, use_curses, debug;

int main(int argc, char **argv) {
  int mode, ret, sockfd, i, writebufflen;
  char *execstr;
  krb5_context context;
  krb5_ccache ccache;
  char *my_principal_string;
  krb5_address local_address, foreign_address;
  struct hostent *lhent, *fhent;
  struct sockaddr_in faddr, laddr;
  struct in_addr foreignhostaddr;
  size_t faddrlen;
  char hostname[MAXHOSTNAMELEN+1];
  unsigned short port;
  WINDOW *sendwin, *receivewin, *sepwin;
  fd_set fdset;
  struct sigaction sigact;
  char writebuff[1024], startupmsg[2048];
  krb5_int32 seqnumber;
  krb5_principal my_principal;
  krb5_auth_context auth_context;

  use_curses=1;
  debug=0;
  curs_start=0;
  connest=0;
  strcpy(startupmsg, "");

  if ((argc >= 3) && !strcmp(argv[1], "-e")) {
    execstr=strdup(argv[2]);
    argc-=2;
    argv+=2;
  } else {
    execstr=NULL;
  }
  
  if (argc != 2 && argc != 4) {
    fprintf(stderr, "usage: %s <user>\n       %s <user> <host> <port>\n", argv[0], argv[0]);
    exit(1);
  }

  if (argc == 2) mode = MODE_SERVER;
  if (argc == 4) mode = MODE_CLIENT;

  sigact.sa_handler=kill_and_die;
  sigemptyset(&sigact.sa_mask);
  sigact.sa_flags=0;
  sigaction(SIGINT, &sigact, NULL);

  if (mode == MODE_SERVER) {
    /* start listening on the first port we can find */
    port = 2050;
    sockfd=socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
      perror("creating socket");
      exit(2);
    }

    memset(&laddr, 0, sizeof(laddr));
    laddr.sin_family=AF_INET;
    laddr.sin_addr.s_addr=htonl(INADDR_ANY);
    laddr.sin_port=htons(port);
    
    while ((ret=bind(sockfd, (struct sockaddr *) &laddr, sizeof(laddr))) != 0) {
      if (errno == EADDRINUSE) {
	port++;
	laddr.sin_port=htons(port);
      } else {
	fprintf(stderr, "%i\n", ret);
	perror("binding socket");
	exit (2);
      }
    }
    
    ret=listen(sockfd, 5);
    if (ret != 0) {
      perror("listening on socket");
      exit(2);
    }

    send_connect_message(argv[1], port, execstr);

    printf("waiting for connection on port %i .... \n", port);
    memset(&faddr, 0, sizeof(faddr));
    faddrlen=sizeof(faddr);
    newsockfd = accept(sockfd, (struct sockaddr *) &faddr, &faddrlen);
    if (newsockfd < 0) {
      perror("accepting connection");
      fprintf(stderr, "%i\n", errno);
      exit(0);
    }
    connest=1;
    printf("connection established.\n");
    close(sockfd);

  } else if (mode == MODE_CLIENT) {
    sockfd=socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
      perror("creating socket");
      exit(2);
    }

    fhent=gethostbyname(argv[2]);
    if (!fhent) {
      fprintf(stderr, "Could not resolve hostname %s\n", argv[2]);
      exit(1);
    }
    memset(&faddr, 0, sizeof(faddr));
    /* memcpy(&foreignhostaddr, fhent->h_addr, sizeof(fhent->h_addr)); */
    memcpy(&foreignhostaddr, fhent->h_addr, fhent->h_length);
    faddr.sin_family=AF_INET;
    faddr.sin_addr = foreignhostaddr;
    port=atoi(argv[3]);
    faddr.sin_port=htons(port);
    
    ret=connect(sockfd, (struct sockaddr *) &faddr, sizeof(faddr));
    if (ret != 0) {
      perror("connecting socket");
      exit(2);
    }
    newsockfd = sockfd;
    connest=1;
    printf("connected.\n");
  }

  /* kerberos set up for both client and server */
  putenv("KRB5_KTNAME=/dev/null"); /* kerberos V can kiss my pasty white ass */
  krb5_init_context(&context);
  krb5_cc_default(context, &ccache);
  krb5_cc_get_principal(context, ccache, &my_principal);
  krb5_unparse_name(context, my_principal, &my_principal_string);
  if (debug) printf("DEBUG: you are %s\n", my_principal_string);
  
  /* get our local address */
  local_address.addrtype=ADDRTYPE_INET;
  local_address.length=sizeof(unsigned long);
  gethostname(hostname, MAXHOSTNAMELEN);
  lhent=gethostbyname(hostname);
  if(!lhent) {
    fprintf(stderr, "Could not resolve hostname %s\n", hostname);
    exit(1);
  }
  local_address.contents=malloc(sizeof(unsigned long));
  memcpy(local_address.contents, lhent->h_addr, sizeof(unsigned long));

  /* get the foreign address */
  foreign_address.addrtype=ADDRTYPE_INET;
  foreign_address.length=sizeof(unsigned long);
  if (mode == MODE_CLIENT) {
    fhent=gethostbyname(argv[2]);
    if (!fhent) {
      fprintf(stderr, "Could not resolve hostname %s\n", argv[2]);
      exit(1);
    }
    foreign_address.contents=malloc(sizeof(unsigned long));
    memcpy(foreign_address.contents, fhent->h_addr, sizeof(unsigned long));
  } else if (mode == MODE_SERVER) {
    struct sockaddr_in *foo;
    
    foo=(struct sockaddr_in *) &faddr;
    foreign_address.contents=malloc(sizeof(unsigned long));
    memcpy(foreign_address.contents, &(foo->sin_addr), sizeof(unsigned long));
  }

  if (mode == MODE_SERVER) {
    krb5_creds in_creds, *out_creds;
    krb5_ticket *inticket = NULL;
    krb5_data msg;
    krb5_principal clprinc;
    char *fprincipal, *clprincstr;
    int i;
    
    /* get the krbtgt/REALM@REALM from the cache into out_creds */
    memset ((char*)&in_creds, 0, sizeof(in_creds));
    krb5_cc_get_principal(context, ccache, &in_creds.client);
    krb5_build_principal_ext(context, &in_creds.server,
			     krb5_princ_realm(context, in_creds.client)->length,
			     krb5_princ_realm(context, in_creds.client)->data,
			     6, "krbtgt",
			     krb5_princ_realm(context, in_creds.client)->length,
			     krb5_princ_realm(context, in_creds.client)->data,
			     0);
    krb5_get_credentials(context, KRB5_GC_CACHED, ccache, 
			 &in_creds, &out_creds);

    /* send over the user_user ticket */
    netwritedata(newsockfd, out_creds->ticket.data, out_creds->ticket.length);

    /* initialize the auth_context */
    krb5_auth_con_init(context, &auth_context);
    krb5_auth_con_setflags(context, auth_context, KRB5_AUTH_CONTEXT_DO_SEQUENCE);
    krb5_auth_con_setaddrs(context, auth_context, &local_address, &foreign_address);
    krb5_auth_con_setuseruserkey(context, auth_context, &out_creds->keyblock);


    /* read the mk_req data sent by the client */
    msg.length=netreaddata(newsockfd, &msg.data);
    if (debug) printf("read message, length was %i\n", msg.length);
    i=krb5_rd_req(context, &auth_context, &msg, NULL, NULL, NULL, &inticket);
    if (debug) printf("read message with rd_req, return was %i\n", i);
    free(msg.data);

    fprincipal=malloc(1024);
    krb5_unparse_name(context, inticket->enc_part2->client, &fprincipal);
    strcat(startupmsg, "Foreign principal authenticates as ");
    strcat(startupmsg, fprincipal);
    strcat(startupmsg, "\n\n");

    /* this is a little wrong, the argv[1] may have @ATHENA.MIT.EDU */ /***** need to fix *****/
    krb5_parse_name(context, argv[1], &clprinc);
    krb5_unparse_name(context, clprinc, &clprincstr);
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
    int i;

    krb5_auth_con_init(context, &auth_context);
    krb5_auth_con_setflags(context, auth_context, KRB5_AUTH_CONTEXT_DO_SEQUENCE);
    krb5_auth_con_setaddrs(context, auth_context, &local_address, &foreign_address);

    /* get the principal */
    /*    i=netreaddata(newsockfd, fprincipal);
    if (debug) printf("got foreign principal %s over the wire\n", fprincipal);
    */
    
    /* read the ticket sent by the server */
    tkt_data.length=netreaddata(newsockfd, &tkt_data.data);
    if (debug) printf("got the ticket, length was %i\n", tkt_data.length);

    memset ((char*)&creds, 0, sizeof(creds));
    
    /* parse the foreign principal into creds.server */
    krb5_parse_name(context, argv[1], &creds.server);    
    /* insert our own principal in creds.client */
    krb5_cc_get_principal(context, ccache, &creds.client);
    
    /* get user_user ticket */
    creds.second_ticket = tkt_data;

    i=krb5_get_credentials(context, KRB5_GC_USER_USER, ccache, &creds, &new_creds);
    if (i) {
      com_err(argv[0], i, "getting user to user credentials");
      netkill(newsockfd);
      exit(1);
    }
    if (debug) printf("Got the user_user ticket!\n");

    /* do the mk_req and send the ticket to the server */
    i=krb5_mk_req_extended(context, &auth_context, AP_OPTS_USE_SESSION_KEY,
			   NULL, new_creds, &out_ticket);

    netwritedata(newsockfd, out_ticket.data, out_ticket.length);
    if (debug) printf("sent mk req message, return was %i\n", i);

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
    receivewin=newwin(LINES/2-1, COLS, 0, 0);
    sepwin=newwin(1, COLS, LINES/2, 0);
    sendwin=newwin(LINES/2-1, COLS, LINES/2+1, 0);

    nodelay(sendwin, 1);
    idlok(sendwin, 1);
    scrollok(sendwin, 1);
    idlok(receivewin, 1);
    scrollok(receivewin, 1);

    for (i=0; i<COLS; i++) {
      waddstr(sepwin, "-");
    }

    wmove(receivewin, 0, 0);
    wmove(sendwin, 0, 0);

    waddstr(receivewin, startupmsg);
  
    wrefresh(receivewin);
    wrefresh(sendwin);
    wrefresh(sepwin);
  }


  for (;;) {
    int i;
    struct timeval timeout;

    timeout.tv_sec=0;
    timeout.tv_usec=10000;

    FD_ZERO(&fdset);
    FD_SET(newsockfd, &fdset);
    if (!use_curses) {
      FD_SET(fileno(stdin), &fdset);
    }
    select(newsockfd+1, &fdset, NULL, NULL, &timeout);

    if (FD_ISSET(newsockfd, &fdset)) {
      /* decrypt and print the incomming message */
      krb5_data msg, encmsg;
      encmsg.length=netreaddata(newsockfd, &encmsg.data);
      if (debug) {
	krb5_auth_con_getremoteseqnumber(context, auth_context, &seqnumber);
	printf("before remote seq is %i\n", seqnumber);
      }
      i=krb5_rd_priv(context, auth_context, &encmsg, &msg, NULL);
      if (debug) {
	krb5_auth_con_getremoteseqnumber(context, auth_context, &seqnumber);
	printf("after remote seq is %i\n", seqnumber);
      }

      if (i && debug) {
	com_err(argv[0], i, "doing rd_priv");
	continue;
      }
	
      if (use_curses) {
	waddstr(receivewin, msg.data);
	wrefresh(receivewin);
	wrefresh(sendwin);
      } else {
	printf("%s",msg.data);
      }
      /* free(msg.data); */  /* this is the trouble line */
      free(encmsg.data);
    } else if ((use_curses==0) && FD_ISSET(fileno(stdin), &fdset)) {
      /* read from the line */
      krb5_data msg, encmsg;
      char *foobuff;

      foobuff=malloc(1024);
      fgets(foobuff, 1024, stdin);
      if (foobuff[strlen(foobuff) - 1] == '\n')
	foobuff[strlen(foobuff) - 1] = 0;


      /* we have a whole line now, send it off */ /* this is duplicated code from below */
      strcat(foobuff, "\n");
      
      msg.data=foobuff;
      msg.length=strlen(foobuff)+1;
      if (debug) {
	krb5_auth_con_getlocalseqnumber(context, auth_context, &seqnumber);
	printf("before local seq is %i\n", seqnumber);
      }
      i=krb5_mk_priv(context, auth_context, &msg, &encmsg, NULL);
      if (debug) {
	krb5_auth_con_getlocalseqnumber(context, auth_context, &seqnumber);
	printf("after local seq is %i\n", seqnumber);
      }

      if (i && debug) com_err("ktalk", i, "making priv");
      netwritedata(newsockfd, encmsg.data, encmsg.length);
      free(encmsg.data);
    } else if (use_curses==1) {
      /* read from the sending window */
      krb5_data msg, encmsg;
      int j, x, y;

      j=wgetch(sendwin);
      if (j == ERR) continue;
      
      if (j == 8 || j == 127) {
	getyx(sendwin, y, x);
	if (x>0) {
	  wmove(sendwin, y, x-1);
	  waddch(sendwin, ' ');
	  wmove(sendwin, y, x-1);
	  wrefresh(sendwin);
	  writebufflen--;
	}
	continue;
      }

      if (j>127 || ((j<32) && (j!=10) && (j!=13))) continue;

      *(writebuff+writebufflen)=j;
      writebufflen++;
      waddch(sendwin, j);
      wrefresh(sendwin);
      
      if (j!='\n' && j!='\r') continue;

      /* we have a whole line now, send it off */
      *(writebuff+writebufflen)='\0';
      msg.data=writebuff;
      msg.length=strlen(writebuff)+1;
      i=krb5_mk_priv(context, auth_context, &msg, &encmsg, NULL);
      if (i && debug) com_err("uu-server", i, "making priv");
      netwritedata(newsockfd, encmsg.data, encmsg.length);
      writebufflen=0;
      free(encmsg.data);
    }
  }
  
}


int netread(int fd, char *ptr, int nbytes) {
  int nleft, nread;

  nleft = nbytes;
  while (nleft > 0) {
    nread=read(fd, ptr, nleft);
    if (nread < 0)  return(nread);
    else if (nread == 0) break;
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
      continue;
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


void netkill(int fd) {
  /* bad hack, i know.  I won't let you type binary characters anyway :-) */
  if (debug && !use_curses) printf("Sent kill message\n");
  netwritedata(fd, "\0\0\0Destruct\0", 12);
}


int netreaddata(int fd, char **p) {
  int i;
  char *ptr;

  i = netreadlen(fd);
  if (i <= 0 || i > 1024)
    return -1;
  
  ptr = malloc(i);
  netread(fd, ptr, i);
  if (i == 12 && memcmp("\0\0\0Destruct\0", ptr, i) == 0)
    leave();

  *p = ptr;
  
  return i;
}


void send_connect_message(char *recip, int port, char *execstr) {
  char hostname[MAXHOSTNAMELEN+1];
  ZNotice_t notice;
  char *list[2];
  char msg[2048];
  char *sender, *foo;
  int i;

  gethostname(hostname, MAXHOSTNAMELEN);
  if (!strcasecmp(hostname+(strlen(hostname)-8), ".mit.edu")) *(hostname+(strlen(hostname)-8))='\0';
  
  ZInitialize();

  sender = strdup(ZGetSender());
  foo = strstr(sender, "@ATHENA.MIT.EDU");
  if (foo)
    *foo='\0';

  if (execstr) {
    i=fork();
    if (i) {
      wait3(NULL, WNOHANG, NULL);
      return;
    }

    foo=malloc(10);
    sprintf(foo, "%i", port);
    i=execlp(execstr, execstr, sender, hostname, foo, NULL);
    if (i) {
      fprintf(stderr, "could not exec %s to send connection message\n", execstr);
      leave();
    }
    free(foo);
    return;
  }  

  sprintf(msg, "This user is requesting a krb5 user to user encrypted communication channel.\n"
	  "To open the channel type:\n"
	  "\n   add ktools\n"
	  "   ktalk %s %s %i\n"
	  "\nat the Athena%% prompt.\n",
	  sender, hostname, port);

  memset(&notice, 0, sizeof(notice));
  notice.z_kind=ACKED; 
  notice.z_class="message";
  notice.z_class_inst="personal";
  notice.z_recipient = strdup(recip);
  notice.z_default_format="Class $class, Instance $instance:\nTo: @bold($recipient) at $time $date\nFrom: @bold{$1 <$sender>}\n\n$2"; 
  notice.z_sender=ZGetSender();
  notice.z_opcode="";
  
  list[0]="Advertise here";
  list[1] = strdup(msg);
  
  ZSendList(&notice, list, 2, ZAUTH);
  ZFreeNotice(&notice);
}


void leave() {
  if (debug && !use_curses) printf("going to leave(), connest is %i\n", connest);
  if (curs_start) endwin();
  exit(0);
}

void kill_and_die() {
  if (connest) netkill(newsockfd);
  leave();
}

/*
 * Local Variables:
 * mode:C
 * c-basic-offset:2
 * End:
 */
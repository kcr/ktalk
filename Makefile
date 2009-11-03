CC=gcc

#Solaris
LIBS=-L/usr/athena/lib -lcurses -lzephyr -lkrb4 -lkrb5 -lcrypto -ldes425 -lsocket -lnsl -lcom_err
CFLAGS=-I/usr/athena/include

#Linux
#LIBS=-L/usr/athena/lib -lzephyr -lkrb4 -lkrb5 -lcrypto -ldes425 -lcom_err
#CFLAGS=-I/usr/athena/include

#NetBSD
#set to include <ncurses.h> in ktalk.c
#LIBS=-L/mit/gnu/lib -lncurses -L/usr/athena/lib -lzephyr -lkrb4 -lkrb5 -lcrypto -ldes425 -lcom_err
#CFLAGS=-I/usr/athena/include -I/mit/gnu/include

#Ultrix
#LIBS=-L/usr/athena/lib -L/mit/krb5/arch/@sys/lib -L/mit/gnu/lib -lncurses_g -lzephyr -lkrb4 -lkrb5 -lcrypto -ldes425 -lcom_err
#CFLAGS=-I/usr/athena/include -I/mit/krb5/arch/@sys/include -I/mit/gnu/include

#IRIX
#set to include <ncurses.h> in ktalk.c
#LIBS=-L/mit/gnu/lib -lncurses -L/usr/athena/lib -lzephyr -lkrb4 -lkrb5 -lcrypto -ldes425 -lcom_err
#CFLAGS=-I/usr/athena/include -I/mit/gnu/include

all: ktalk

ktalk: ktalk.o
	$(CC) -o ktalk ktalk.o $(LIBS)

clean:
	$(RM) ktalk ktalk.o *~

###
# Revised Makefile for Crack v4.1 - AEM, Feb 14 1992
###

LIBS=
CC=		gcc
CFLAGS=		-O2
PWC= 		crack-pwc
FCRYPT= 	crack-fcrypt.o
OBJS= 		crack-lib.o crack-glob.o crack-supp.o crack-sort.o
UFCLIB=		../libdes/libdes.a
TRUNS=		1000

###
# The reason for the direct reference to libufc.a is to get round
# obnoxious problems with ranlibbing a file after copying it on some
# architectures. 
###

$(PWC).which:
	@echo Choosing between Crack.fcrypt and Crack.ufc
	-((../Scripts/do_ufc && make $(PWC).ufc) || make $(PWC).fcrypt)

$(PWC).fcrypt:	$(OBJS) $(FCRYPT) $(PWC).o
		$(CC) $(CFLAGS) -o $(PWC) $(PWC).o $(OBJS) $(FCRYPT) $(LIBS)

$(PWC).ufc:	$(OBJS) $(PWC).o
		$(CC) $(CFLAGS) -o $(PWC) $(PWC).o $(OBJS) $(UFCLIB) $(LIBS)

testrule:	testrule.o crack-lib.o
		$(CC) $(CFLAGS) -o $@ testrule.o crack-lib.o

tester:		tester.o $(OBJS) $(FCRYPT)
		$(CC) $(CFLAGS) -o $@ tester.o $(OBJS) $(FCRYPT)

speedufc:	speeds.c $(OBJS) $(UFC)
		../Scripts/do_ufc
		$(CC) $(CFLAGS) -DT1 -o $@ speeds.c $(OBJS) $(UFCLIB)

speedfcrypt:	speeds.c $(OBJS) $(FCRYPT)
		$(CC) $(CFLAGS) -DT1 -o $@ speeds.c $(OBJS) $(FCRYPT)

speedxform:	speeds.c $(OBJS) $(FCRYPT)
		$(CC) $(CFLAGS) -DT2 -o $@ speeds.c $(OBJS) $(FCRYPT)

speedcrypt:	speeds.c $(OBJS) $(FCRYPT)
		$(CC) $(CFLAGS) -o $@ speeds.c $(OBJS) $(FCRYPT)

tests:		tester speedcrypt speedfcrypt speedxform speedufc
		-tester $(TRUNS)
		-speedcrypt
		-speedfcrypt
		-speedxform
		-speedufc

bytesex: 	bytesex.o
		$(CC) $(CFLAGS) -o $@ bytesex.o

$(FCRYPT):	crack-fcrypt.c crack.h bytesex
		$(CC) $(CFLAGS) `./bytesex` -c crack-fcrypt.c

$(PWC).o:	crack.h conf.h

crack-glob.o:	crack.h

crack-lib.o:	crack.h conf.h

crack-sort.o:	crack.h

crack-supp.o:	crack.h conf.h

testrule.o:	crack.h

crack.h:	crack-glob.h
		touch crack.h

conf.h:

clean:
		-rm -f *.o *.u *.a *.pixie *.Addrs *.Counts
		-rm -f $(PWC) tester bytesex testrule
		-rm -f speedcrypt speedfcrypt speedxform speedufc

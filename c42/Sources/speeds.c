/*
 * This program is copyright Alec Muffett 1991 except for some portions of
 * code in "crack-fcrypt.c" which are copyright Robert Baldwin, Icarus Sparry
 * and Alec Muffett. The author(s) disclaims all responsibility or liability
 * with respect to it's usage or its effect upon hardware or computer
 * systems, and maintain copyright as set out in the "LICENCE" document which
 * accompanies distributions of Crack v4.0 and upwards.
 */

/*  Cray portions Copyright (c) 1992 Tom Hutton. */
#ifdef cray
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#else
#include <sys/time.h>
#include <signal.h>
#endif
#include <stdio.h>

#ifdef cray
/*
 * Clocks to seconds and seconds to clocks
 */

#define CTOS(X)  ((long) ((unsigned) (X) / (long) hz))
#define STOC(X)  ((long) ((X) * hz))

static long hz;
#endif

static int cnt;
#define ITIME	10		/* Number of seconds to run test. */

void
Stop ()
{
    printf ("Did %f %s()s per second.\n",
	    ((float) cnt) / ((float) ITIME),
#ifdef T1
	    "fcrypt"
#else
#ifdef T2
	    "XForm"
#else
	    "crypt"
#endif
#endif
    );
    exit (0);
}
main ()
{
#ifdef	cray
    static long vtime;
#else
    struct itimerval itv;
#endif
    static int quarters[4];

#ifdef cray
    hz = sysconf(_SC_CLK_TCK);      /* get # ticks per second */
    vtime = STOC(ITIME);
#else
    bzero (&itv, sizeof (itv));
#endif

    printf ("Running for %d seconds of virtual time ...\n", ITIME);

#if defined(T1) || defined(T2)
    init_des ();
#endif

#ifdef cray
    for (cnt = 0;cpused() <= vtime; cnt++)
#else
    signal (SIGVTALRM, Stop);
    itv.it_value.tv_sec = ITIME;
    itv.it_value.tv_usec = 0;
    setitimer (ITIMER_VIRTUAL, &itv, NULL);

    for (cnt = 0;; cnt++)
#endif
    {
#ifdef T1
	fcrypt ("fredfred", "eek");
#else
#ifdef T2
	XForm (quarters, 0);
#else
	crypt ("fredfred", "eek");
#endif
#endif
    }
    Stop();
}

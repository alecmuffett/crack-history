#include <stdio.h>

main ()
{
    char *p;
    long int l;

    l = 'a' << 24 | 'b' << 16 | 'c' << 8 | 'd';
    p = (char *) &l;

    if (sizeof (long int) == 4)
    {
#ifndef GCC			/* gcc tends to make a botch of it */
	puts ("-DFDES_4BYTE");
#endif
    } else if (sizeof (long int) == 8)
    {
	puts ("-DFDES_8BYTE");
	l <<= 32;
    } else
    {
	printf ("-DFDES_%dBYTE%c", sizeof (long int), 10);
    }
    if (!strncmp (p, "abcd", 4))
    {
	puts ("-DBIG_ENDIAN");
    } else if (!strncmp (p, "dcba", 4))
    {
	puts ("-DLITTLE_ENDIAN");
    }
    exit (0);
}

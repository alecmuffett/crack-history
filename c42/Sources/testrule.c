#include "crack.h"

void
Log (a, b, c, d, e, f, g)
    char *a, b, c, d, e, f, g;
{
    printf (a, b, c, d, e, f, g);
}

int
main (argc, argv)
    int argc;
    char *argv[];
{
    int i;
    char *ptr;
    char buffer[STRINGSIZE];

    while (!feof (stdin))
    {
	fgets (buffer, STRINGSIZE - 1, stdin);

	Trim (buffer);

	for (i = 1; i < argc; i++)
	{
	    ptr = Mangle (buffer, argv[i]);

	    printf ("'%s'('%s') = '%s'\n",
		    argv[i],
		    buffer,
		    ptr ? ptr : "(rejected)");
	}
    }
    return (0);
}

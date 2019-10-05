#include <stdio.h>
#include <time.h>

main (argc, argv)
    int argc;
    char *argv[];
{
    register int i;
    long int t;

    if (argc < 2)
    {
	exit (1);
    }
    init_des ();

    printf ("%s\n", fcrypt ("fredfred", "fredfred"));

    if (strcmp (fcrypt ("fredfred", "fredfred"), "frxWbx4IRuBBA"))
    {
	printf ("Version of fcrypt() is not compatible with standard.\n");
	exit (0);
    }
    i = atoi (argv[1]);

    printf ("Doing %d fcrypts()\n", i);

    time (&t);
    printf ("%s", ctime (&t));

    while (i--)
    {
	fcrypt ("fredfred", "fredfred");
    }

    time (&t);
    printf ("%s", ctime (&t));

    return (0);
}

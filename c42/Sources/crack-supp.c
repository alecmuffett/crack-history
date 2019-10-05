/*
 * This program is copyright Alec Muffett 1991 except for some portions of
 * code in "crack-fcrypt.c" which are copyright Robert Baldwin, Icarus Sparry
 * and Alec Muffett.  The author(s) disclaims all responsibility or liability
 * with respect to it's usage or its effect upon hardware or computer
 * systems, and maintain copyright as set out in the "LICENCE" document which
 * accompanies distributions of Crack v4.0 and upwards.
 */

#include "crack.h"

#ifdef CRACK_UNAME
#ifndef AMIGA
#include <sys/utsname.h>
int
gethostname (name, namelen)
    char *name;
    int namelen;
{
    struct utsname uts;
    if (uname (&uts))
    {
	return (-1);
    }
    strncpy (name, uts.nodename, namelen - 1);
    return (0);
}
#else
int
gethostname (name, namelen)
    char *name;
    int namelen;
{
    strncpy (name, "dougal", namelen);
    return (0);
}
#endif				/* AMIGA */
#endif				/* CRACK_UNAME */

/* log anything to datafile. */

void
Log (fmt, a, b, c, d, e, f, g, h, i, j)
    char *fmt;
    long int a, b, c, d, e, f, g, h, i, j;
{
    long t;

    time (&t);
    printf ("pwc: %-15.15s ", ctime (&t) + 4);
    printf (fmt, a, b, c, d, e, f, g, h, i, j);
    fflush (stdout);
}
/* print a guess, giving a single place to mod where necessary */

void
PrintGuess (eptr, guess)
    register struct USER *eptr;
    char *guess;
{
    eptr -> done = 1;
    eptr -> passwd_txt = Clone (guess);	/* ESSENTIAL to FeedBack() */

    if (!eptr -> passwd_txt)
    {
	eptr -> passwd_txt = "<Ran out of memory logging this password>";
    }
    Log ("Guessed %s%s (%s in %s) [%s] %s\n",
	 (eptr -> passwd.pw_uid ? "" : "ROOT PASSWORD "),
	 eptr -> passwd.pw_name,
	 eptr -> passwd.pw_shell,
	 eptr -> filename,
	 guess,
	 eptr -> passwd.pw_passwd);

    if (mail_bool)
    {
	char dobuff[STRINGSIZE];

	sprintf (dobuff, "%s %s", nastygram, eptr -> passwd.pw_name);
	system (dobuff);
    }
}


/* write a pointfile out */

int
SetPoint (dict, rule, usernum, username)
    char *dict;
    char *rule;
    int usernum;
    char *username;
{
    FILE *fp;
    long t;

    if (!(fp = fopen (pointfile, "w")))
    {
	perror (pointfile);
	return (-1);
    }
    time (&t);

    fprintf (fp, "host=%s pid=%d pointtime=%s", this_hostname, pid, ctime (&t));
    fprintf (fp, "%s\n", this_hostname);
    fprintf (fp, "%s\n", dict);
    fprintf (fp, "%s\n", rule);
    fprintf (fp, "%d\n", usernum);
    fprintf (fp, "%s\n", username);

    fclose (fp);

    return (0);
}
/* read a pointfile in... */

int
GetPoint (pf)
    char *pf;
{
    FILE *fp;
    char buffer[STRINGSIZE];

    if (!(fp = fopen (pf, "r")))
    {
	perror (pf);
	return (-1);
    }
    /* junk */
    if (!fgets (buffer, STRINGSIZE, fp))
    {
	return (-2);
    }
    /* hostname */
    if (!fgets (old_hostname, STRINGSIZE, fp))
    {
	return (-3);
    }
    /* dictname */
    if (!fgets (old_dictname, STRINGSIZE, fp))
    {
	return (-4);
    }
    /* rule */
    if (!fgets (old_rule, STRINGSIZE, fp))
    {
	return (-5);
    }
    /* usernum */
    if (!fgets (buffer, STRINGSIZE, fp))
    {
	return (-6);
    }
    /* username */
    if (!fgets (old_username, STRINGSIZE, fp))
    {
	return (-7);
    }
    Trim (old_hostname);

    if (strcmp (old_hostname, this_hostname))
    {
	return (-8);
    }
    Trim (old_dictname);
    Trim (old_rule);

    old_usernum = atoi (buffer);

    Trim (old_username);

    fclose (fp);

    return (0);
}

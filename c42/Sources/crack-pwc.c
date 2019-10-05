/*
 * This program is copyright Alec Muffett 1991 except for some portions of
 * code in "crack-fcrypt.c" which are copyright Robert Baldwin, Icarus Sparry
 * and Alec Muffett.  The author(s) disclaims all responsibility or liability
 * with respect to it's usage or its effect upon hardware or computer
 * systems, and maintain copyright as set out in the "LICENCE" document which
 * accompanies distributions of Crack v4.0 and upwards.
 */

#include "crack.h"

#define DOTFILESIZE	1024
#define WORDSTACKSIZE	512

/*
 * crack-pwc.c - an optimised password cracker. (c) ADE Muffett, Feb 1992. If
 * this won't break your password file, it's unlikely that anything else
 * will.
 */

/* trap a signal on shutdown */

void
CatchTERM ()
{
    /* bury magnets */
    Log ("Caught a SIGTERM! Commiting suicide...\n");
    /* swallow the rapture */
    Log ("<argh!>\n");
    /* let's gather feathers */
    sync ();
    /* don't fall on me */
    exit (0);
    /* 'Fall on Me' by R.E.M. */
}
/* jump ':' separated fields in an input */

char *
PWSkip (p)
    register char *p;
{
    while (*p && *p != ':')
    {
	p++;
    }
    if (*p)
    {
	*p++ = '\0';
    }
    return (p);
}

char *
Archive (myword)
    register char *myword;
{
    register int i;
    register struct DICT *ptr;
    static struct DICT *arch_root;

    for (ptr = arch_root; ptr; ptr = ptr -> next)
    {
	if (!STRCMP (ptr -> word, myword))
	{
	    return (ptr -> word);
	}
    }

    i = strlen (myword);

    ptr = (struct DICT *) malloc (sizeof (struct DICT) + i);

    if (ptr)
    {
	strcpy (ptr -> word, myword);
	ptr -> word[i] = '\0';
	ptr -> next = arch_root;
	arch_root = ptr;
    } else
    {
	Log ("Archive/malloc() failed! Fatal lack of memory!\n");
	exit (1);
    }

    return (ptr -> word);
}
/* parse and store a password entry */

struct USER *
Parse (buffer)
    register char *buffer;
{
    register char *p;
    register struct USER *retval;

    retval = (struct USER *) malloc (sizeof (struct USER));

    if (!retval)
    {
	Log ("Parse/malloc() failed! Fatal lack of memory!\n");
	exit (1);
    }
    retval -> next = retval -> across = NULL;
    retval -> passwd_txt = NULL;
    retval -> done = 0;
    Trim (buffer);

    p = PWSkip (buffer);
    retval -> filename = Archive (buffer);

    p = Clone (p);
    if (!p)
    {
	Log ("Parse/Clone() failed! Fatal lack of memory!\n");
	exit (1);
    }
    retval -> passwd.pw_name = p;

    p = PWSkip (p);
    retval -> passwd.pw_passwd = p;

    p = PWSkip (p);
    retval -> passwd.pw_uid = atoi (p);

    p = PWSkip (p);
    retval -> passwd.pw_gid = atoi (p);

    p = PWSkip (p);
    retval -> passwd.pw_gecos = p;

    p = PWSkip (p);
    retval -> passwd.pw_dir = p;

    p = PWSkip (p);
    retval -> passwd.pw_shell = p;

    return (retval);
}
/* load pre-formatted password entries off stdin into linked list */

int
LoadData ()
{
    int i;
    char *ptr;
    char salt[2];
    char buffer[STRINGSIZE];
    long int numlines;
    long int numentries;
    register struct USER *new_element;
    register struct USER *current_line;

    numlines = 0L;
    numentries = 0L;
    current_line = NULL;
    salt[0] = salt[1] = '*';

    while (fgets (buffer, STRINGSIZE, stdin))
    {
	if (!*buffer || isspace (*buffer))
	{
	    continue;
	}
	new_element = Parse (buffer);
	ptr = new_element -> passwd.pw_passwd;

	if (!ptr[0])
	{
	    Log ("Warning! %s (%s in %s) has a NULL password!\n",
		 new_element -> passwd.pw_name,
		 new_element -> passwd.pw_shell,
		 new_element -> filename);
	    continue;
	}
	if (strchr (ptr, '*') ||
	    strchr (ptr, '!') ||
	    strchr (ptr, ' '))
	{
	    Log ("User %s (in %s) has a locked password:- %s\n",
		 new_element -> passwd.pw_name,
		 new_element -> filename,
		 new_element -> passwd.pw_passwd);
	    continue;
	}
	i = strlen (ptr);

	if (i < 13)
	{
	    Log ("User %s (in %s) has a short pw_passwd field - skipping.\n",
		 new_element -> passwd.pw_name,
		 new_element -> filename);
	    continue;
	}
	if (i > 13)
	{
	    Log ("User %s (in %s) has a long pw_passwd field - truncating.\n",
		 new_element -> passwd.pw_name,
		 new_element -> filename);
	    ptr[13] = '\0';
	}
	numentries++;

	if (ptr[0] == salt[0] && ptr[1] == salt[1])
	{
	    new_element -> across = current_line;
	    current_line = new_element;
	} else
	{
	    if (current_line)
	    {
		current_line -> next = userroot;
	    }
	    userroot = current_line;
	    current_line = new_element;
	    numlines++;
	    salt[0] = ptr[0];
	    salt[1] = ptr[1];
	}
    }

    if (current_line)		/* last one tends to hang about */
    {
	current_line -> next = userroot;
	userroot = current_line;
	numlines++;
    }
    --numlines;

    if (numentries)
    {
	Log ("Loaded %ld password entries with %ld different salts: %d%%\n",
	     numentries,
	     numlines,
	     ((numlines * 100) / numentries));
    } else
    {
	Log ("No input supplied: everything removed by feedback ?\n");
    }
    return (numentries);
}
/* and load rules from a standard file into a similar list */

int
LoadRules (file, rootpos)
    char *file;
    struct RULE **rootpos;
{
    FILE *fp;
    int numrules;
    struct RULE fencepost;
    register struct RULE *addinto;
    register struct RULE *scratch;
    char buffer[STRINGSIZE];

    if (!(fp = fopen (file, "r")))
    {
	Log ("cannot open rulefile %s\n", file);
	perror (file);
	return (-1);
    }
    numrules = 0;
    addinto = &fencepost;
    addinto -> next = (struct RULE *) 0;

    while (fgets (buffer, STRINGSIZE, fp))
    {
	Trim (buffer);

	if (!buffer[0] || buffer[0] == '#')
	{
	    continue;
	}
	scratch = (struct RULE *) malloc (sizeof (struct RULE));

	if (!scratch)
	{
	    Log ("LoadRules/malloc() failed! Fatal lack of memory!\n");
	    exit (1);
	}
	scratch -> rule = Clone (buffer);

	if (!scratch -> rule)
	{
	    Log ("LoadRules/Clone() failed! Fatal lack of memory!\n");
	    exit (1);
	}
	scratch -> next = (struct RULE *) 0;
	addinto -> next = scratch;
	addinto = scratch;
	numrules++;
    }

    fclose (fp);
    Log ("Loaded %d rules from '%s'.\n", numrules, file);
    *rootpos = fencepost.next;
    return (numrules);
}
/* load a dictionary into a linked list, and sort it */

long int
LoadDict (file, rule, contdict)
    char *file;
    char *rule;
    int contdict;
{
    int i;
    int memfilled;
    long int nelem;
    long int rejected;
    register char *mangle;
    register struct DICT *scratch;
    char pipebuff[STRINGSIZE];

    static FILE *fp;
    char buffer[STRINGSIZE];

    if (contdict && fp)
    {
	goto files_open;
    }

    sprintf(pipebuff, "%s %s", smartcat, file);

    if (!(fp = (FILE *) popen (pipebuff, "r")))
    {
	perror (pipebuff);
	return (0);
    }

  files_open:

    nelem = 0;
    rejected = 0;
    memfilled = 0;
    dictroot = (struct DICT *) 0;

    Log ("%s rule '%s' to file '%s'\n",
	 contdict ? "Continuing" : "Applying",
	 rule,
	 file);

    while (fgets (buffer, STRINGSIZE, fp))
    {
	Trim (buffer);

	if (!buffer[0] || buffer[0] == '#')
	{
	    continue;
	}
	mangle = Mangle (buffer, rule);

	if (!mangle)
	{
	    rejected++;

	    if (verbose_bool)
	    {
		Log ("Rejected '%s' due to rule specs.\n", buffer);
	    }
	    continue;
	}
	if (dictroot && !strncmp (mangle, dictroot -> word, pwlength))
	{
	    rejected++;

	    if (verbose_bool)
	    {
		Log ("Rejected '%s'; duplicated to %d chars.\n", buffer,
		     pwlength);
	    }
	    continue;
	}
	i = strlen (mangle);

	if (i > pwlength)
	{
	    i = pwlength;
	}
	scratch = (struct DICT *) malloc (sizeof (struct DICT) + i);

	if (!scratch)
	{
	    Log ("LoadDict/malloc() failed! Shameful lack of memory!\n");
	    memfilled = 1;
	    goto words_loaded;
	}
	strncpy (scratch -> word, mangle, i);
	scratch -> word[i] = '\0';
	scratch -> next = dictroot;
	dictroot = scratch;
	nelem++;

	if (verbose_bool)
	{
	    Log ("Loaded '%s' as '%s' using '%s'\n", buffer,
		 scratch -> word, rule);
	}
    }

    if (pipebuff[0])
    {
	pclose (fp);
    } else
    {
	fclose (fp);
    }

    fp = (FILE *) 0;

  words_loaded:

    if (nelem == 0)
    {
	return (0);
    }
    Log ("Rejected %ld words on loading, %ld words left to sort\n",
	 rejected, nelem);

    dictroot = (struct DICT *) SortDict (dictroot, nelem);

    if (memfilled)
    {
	nelem = -nelem;
    }
    return (nelem);		/* not strict number anymore... */
}
/* lose the current dictionary */

int
DropDict ()
{
    register struct DICT *scratch1;
    register struct DICT *scratch2;

    scratch1 = dictroot;
    while (scratch1)
    {
	scratch2 = scratch1 -> next;
	free (scratch1);
	scratch1 = scratch2;
    }
    return (0);
}
/*
 * write a feedback file if there is anything to save - return number
 * uncracked users
 */

int
FeedBack (log_notdone)
    int log_notdone;
{
    register FILE *fp;
    static char fmt[] = "%s:%s:%s:%s\n";
    register struct USER *head;
    register struct USER *arm;
    int done;
    int notdone;

    notdone = done = 0;

    if (verbose_bool)
    {
	Log ("Sweeping data looking for feedback.\n");
    }
    fp = (FILE *) 0;

    for (head = userroot; head; head = head -> next)
    {
	for (arm = head; arm; arm = arm -> across)
	{
	    if (arm -> done)
	    {
		done++;
		/* horrible little hack, vile, sick, I love it */
		if (!fp)
		{
		    if (!(fp = fopen (feedbackfile, "w")))
		    {
			perror (feedbackfile);
			return (-1);
		    }
		    if (verbose_bool)
		    {
			Log ("Feedback file opened for writing.\n");
		    }
		}
		fprintf (fp, fmt, feedback_string,
			 arm -> passwd.pw_passwd, "Y", arm -> passwd_txt);
	    } else
	    {
		notdone++;
		if (log_notdone)
		{
		    if (!fp)	/* and again !!! heheheheheheh */
		    {
			if (!(fp = fopen (feedbackfile, "w")))
			{
			    perror (feedbackfile);
			    return (-1);
			}
			if (verbose_bool)
			{
			    Log ("Feedback file opened for writing.\n");
			}
		    }
		    /* I think I'm going slightly warped */
		    fprintf (fp, fmt, feedback_string,
			     arm -> passwd.pw_passwd, "N", "");
		}
	    }

	}
    }
    if (fp)
    {
	fclose (fp);
	Log ("Closing feedback file.\n");
    }
    Log ("FeedBack: %d users done, %d users left to crack.\n", done, notdone);
    return (notdone);
}
/* try a chain of users with the same salt */

int
TryManyUsers (eptr, guess)	/* returns 0 if all done this chain */
    register struct USER *eptr;
    char *guess;
{
    register int retval;
    char guess_crypted[STRINGSIZE];

    if (eptr -> done && !eptr -> across)
    {
	return (0);
    }
    strcpy (guess_crypted, crypt (guess, eptr -> passwd.pw_passwd));

    retval = 0;

    while (eptr)
    {
	if (verbose_bool)
	{
	    Log ("Trying '%s' on %s from line %s\n",
		 guess,
		 eptr -> passwd.pw_name,
		 eptr -> filename);
	}
	if (!eptr -> done && !STRCMP (guess_crypted, eptr -> passwd.pw_passwd))
	{
	    guess[pwlength] = '\0';
	    PrintGuess (eptr, guess);
	}
	retval += (!(eptr -> done));
	eptr = eptr -> across;
    }

    return (retval);
}
/* try a word on an individual */

int
TryOneUser (eptr, guess)	/* returns non-null on guessed user */
    register struct USER *eptr;
    register char *guess;
{
    if (!guess || !*guess || eptr -> done)
    {
	return (0);
    }
    if (verbose_bool)
    {
	Log ("Trying '%s' on %s from %s\n",
	     guess,
	     eptr -> passwd.pw_name,
	     eptr -> filename);
    }
    if (strcmp (crypt (guess, eptr -> passwd.pw_passwd),
		eptr -> passwd.pw_passwd))
    {
	return (0);
    }

    guess[pwlength] = '\0';
    PrintGuess (eptr, guess);

    return (1);
}
/* frontend to TryOneUser() to save hassle */

int
WordTry (entry_ptr, guess)
    register struct USER *entry_ptr;
    register char *guess;
{
    struct RULE *ruleptr;
    register char *mangle;

    if (!guess[0] || !guess[1])
    {
	return (0);
    }
    for (ruleptr = gecosroot; ruleptr; ruleptr = ruleptr -> next)
    {
	if (mangle = Mangle (guess, ruleptr -> rule))
	{
	    if (TryOneUser (entry_ptr, mangle))
	    {
		return (1);
	    }
	}
    }
    return (0);
}
/* Special manipulations for the GECOS field and dotfiles */

int
ParseBuffer (entry_ptr, buffer, advanced)
    register struct USER *entry_ptr;
    char *buffer;
    int advanced;
{
    int wordcount;
    register int i;
    register int j;
    register char *ptr;
    char junk[STRINGSIZE];
    char *words[WORDSTACKSIZE];

    /* zap all punctuation */
    for (ptr = buffer; *ptr; ptr++)
    {
	if (ispunct (*ptr) || isspace (*ptr))
	{
	    *ptr = ' ';
	}
    }

    /* break up all individual words */
    wordcount = 0;
    ptr = buffer;
    while (*ptr)
    {
	while (*ptr && isspace (*ptr))
	{
	    ptr++;
	}

	if (*ptr)
	{
	    words[wordcount++] = ptr;
	    if (wordcount >= WORDSTACKSIZE)
	    {
		Log ("ParseBuffer: Abort: Stack Full !\n");
		return (0);
	    }
	}
	while (*ptr && !isspace (*ptr))
	{
	    ptr++;
	}

	if (*ptr)
	{
	    *(ptr++) = '\0';
	}
    }

    words[wordcount] = (char *) 0;

    /* try all the words individually */
    if (verbose_bool)
    {
	Log ("Trying individual words\n");
    }
    for (i = 0; i < wordcount; i++)
    {
	if (WordTry (entry_ptr, words[i]))
	{
	    return (1);
	}
    }

    if (!advanced)
    {
	return (0);
    }
    /* try pairings of words */
    if (verbose_bool)
    {
	Log ("Trying paired words\n");
    }
    for (j = 1; j < wordcount; j++)
    {
	for (i = 0; i < j; i++)
	{
	    /* Skip initials for next pass */
	    if (!words[i][1] || !words[j][1])
	    {
		continue;
	    }
	    strcpy (junk, words[i]);
	    strcat (junk, words[j]);

	    if (WordTry (entry_ptr, junk))
	    {
		return (1);
	    }
	    strcpy (junk, words[j]);
	    strcat (junk, words[i]);

	    if (WordTry (entry_ptr, junk))
	    {
		return (1);
	    }
	}
    }

    /* try initials + words */
    if (verbose_bool)
    {
	Log ("Trying initial'ed words\n");
    }
    for (j = 1; j < wordcount; j++)
    {
	for (i = 0; i < j; i++)
	{
	    junk[0] = words[i][0];
	    junk[0] = CRACK_TOUPPER (junk[0]);
	    strcpy (junk + 1, words[j]);
	    if (WordTry (entry_ptr, junk))
	    {
		return (1);
	    }
	}
    }

    return (0);
}
/* run over password entries looking for passwords */

void
Pass1 ()
{
    struct USER *head;
    char junk[DOTFILESIZE];
    register struct USER *this;

#ifdef CRACK_DOTFILES
#ifdef CRACK_DOTSANE
#include <sys/types.h>
#include <sys/stat.h>
    struct stat sb;
#endif	/* CRACK_DOTSANE */
    int i;
    int j;
    FILE *fp;
    char filename[STRINGSIZE];
    static char *dotfiles[] =
    {
	".plan",
	".project",
	".signature",
	(char *) 0
    };
#endif	/* CRACK_DOTFILES */

    Log ("Starting pass 1 - password information\n");

    for (head = userroot; head; head = head -> next)
    {
	for (this = head; this; this = this -> across)
	{
	    strcpy (junk, this -> passwd.pw_gecos);

	    if (WordTry (this, this -> passwd.pw_name) ||
		ParseBuffer (this, junk, 1))
	    {
		continue;
	    }
#ifdef CRACK_DOTFILES
	    for (i = 0; dotfiles[i]; i++)
	    {
		sprintf (filename, "%s/%s", this -> passwd.pw_dir, dotfiles[i]);
#ifdef CRACK_DOTSANE
		if (stat (filename, &sb) < 0)
		{
		    continue;
		}
		if ((!(sb.st_mode & S_IFREG))
#ifdef S_IFSOCK
		    || ((sb.st_mode & S_IFSOCK) == S_IFSOCK)
#endif	/* S_IFSOCK */
		    )
		{
		    continue;
		}
#endif	/* CRACK_DOTSANE */

		if (!(fp = fopen (filename, "r")))
		{
		    continue;
		}
		j = fread (junk, 1, DOTFILESIZE, fp);
		fclose (fp);

		if (j <= 2)
		{
		    continue;
		}
		junk[j - 1] = '\0';	/* definite terminator */

		if (verbose_bool)
		{
		    Log ("DOTFILES: Checking %d bytes of %s\n", j, filename);
		}
		if (ParseBuffer (this, junk, 0))
		{
		    continue;
		}
	    }
#endif	/* CRACK_DOTFILES */
	}
    }
    return;
}

void
Pass2 (dictfile)
    char *dictfile;
{
    int pointuser;
    struct USER *headptr;
    struct RULE *ruleptr;
    struct DICT *dictptr;

    Log ("Starting pass 2 - dictionary words\n");
    headptr = (struct USER *) 0;
    ruleptr = (struct RULE *) 0;

    /* check if we are recovering from a crash */
    if (recover_bool)
    {
	recover_bool = 0;	/* switch off */

	for (ruleptr = ruleroot;
	     ruleptr && strcmp (ruleptr -> rule, old_rule);
	     ruleptr = ruleptr -> next);

	if (!ruleptr)
	{
	    Log ("Fatal: Ran off end of list looking for rule '%s'\n",
		 old_rule);
	    exit (1);
	}
	for (headptr = userroot;/* skip right number of users */
	     headptr && old_usernum--;
	     headptr = headptr -> next);

	if (!headptr)
	{
	    Log ("Fatal: Ran off end of list looking for user '%s'\n",
		 old_username);
	    exit (1);
	}
    }
    /* start iterating here */
    for (ruleptr = (ruleptr ? ruleptr : ruleroot);
	 ruleptr;
	 ruleptr = ruleptr -> next)
    {
	long int rval;
	int continue_dict;

	/* go to sleep if desired */
	system(pauser);

	continue_dict = 0;

      load_dict:
	rval = LoadDict (dictfile, ruleptr -> rule, continue_dict);

	if (rval == 0)
	{
	    Log ("Oops! I got an empty dictionary! Skipping rule '%s'!\n",
		 ruleptr -> rule);
	    continue;
	}
	pointuser = 0;

	/* iterate all the users */
	for (headptr = (headptr ? headptr : userroot);
	     headptr;
	     headptr = headptr -> next)
	{
	    SetPoint (dictfile,
		      ruleptr -> rule,
		      pointuser++,
		      headptr -> passwd.pw_name);

	    /* iterate all the words */
	    for (dictptr = dictroot;
		 dictptr;
		 dictptr = dictptr -> next)
	    {
		/* skip repeated words... */
		if (!TryManyUsers (headptr, dictptr -> word))
		{
		    break;
		}
	    }
	}

	/* free up memory */
	DropDict ();

	/* write feedback file */
	if (!FeedBack (0))
	{
	    Log ("FeedBack: All Users Are Cracked! Bloody Hell!\n");
	    return;
	}
	/* on next pass, start from top of user list */
	headptr = (struct USER *) 0;

	/* did we REALLY finish this dictionary ? */
	if (rval < 0)
	{
	    continue_dict = 1;
	    goto load_dict;
	}
    }
}

int
main (argc, argv)
    int argc;
    char *argv[];
{
    int i;
    long t;
    int uerr;
    int die_bool = 0;
    FILE *fp;
    char *crack_out;
    extern int optind;
    extern char *optarg;
    static char getopt_string[] = "i:fX:n:r:vml:";

    uerr = 0;

    if (argc == 1)
    {
	uerr++;
    }
    while ((i = getopt (argc, argv, getopt_string)) != EOF)
    {
	switch (i)
	{
	case 'i':
	    strcpy (input_file, optarg);
	    if (!freopen (input_file, "r", stdin))
	    {
		perror (input_file);
		exit (1);
	    }
	    if (!strncmp (input_file, "/tmp/pw.", 7))
	    {
		unlink (input_file);
	    }
	    break;
	case 'm':
	    mail_bool = 1;
	    break;
	case 'f':
	    foreground_bool = 1;
	    break;
	case 'X':
	    remote_bool = 1;
	    strcpy (supplied_name, optarg);
	    break;
	case 'l':
	    pwlength = atoi (optarg);
	    break;
	case 'n':
	    nice_value = atoi (optarg);
	    nice (nice_value);
	    break;
	case 'r':
	    recover_bool = 1;
	    strcpy (recover_file, optarg);
	    break;
	case 'v':
	    verbose_bool = 1;
	    break;
	default:
	case '?':
	    uerr++;
	    break;
	}
    }

    if (optind >= argc)
    {
	uerr++;
    }
    if (uerr)
    {
	fprintf (stderr,
		 "Usage:\t%s -%s dictfile [dictfile...]\n",
		 argv[0],
		 getopt_string);
	exit (1);
    }
    pid = getpid ();

    if (gethostname (this_hostname, STRINGSIZE))
    {
	perror ("gethostname");
    }
    if (!(crack_out = (char *) getenv ("CRACK_OUT")))
    {
	crack_out = ".";
    }
    sprintf (opfile, "%s/out.%s%d", crack_out, this_hostname, pid);

    if (remote_bool)
    {
	sprintf (diefile, "%s", supplied_name);
    } else
    {
	sprintf (diefile, "%s/D%s%d", runtime, this_hostname, pid);
    }
    sprintf (pointfile, "%s/P%s%d", runtime, this_hostname, pid);
    sprintf (feedbackfile, "%s/F%s%d", runtime, this_hostname, pid);

    if (!foreground_bool)
    {
	if (!freopen (opfile, "w", stdout))
	{
	    perror ("freopen(stdout)");
	    exit (1);
	}
	if (!freopen (opfile, "a", stderr))
	{
	    perror ("freopen(stderr)");
	    exit (1);
	}
    }
    /*
     * don't generate a die file unless we are not 'attached' to a
     * terminal...  except when we are remote as well...
     */

    time (&t);

    if (!foreground_bool || (foreground_bool && remote_bool))
    {
	if (!(fp = fopen (diefile, "w")))
	{
	    perror (diefile);
	    exit (1);
	}
	die_bool = 1;
	fprintf (fp, "#!/bin/sh\n");
	fprintf (fp, "# ID=%s.%d start=%s", this_hostname, pid, (char *) ctime (&t));
	fprintf (fp, "kill -TERM %d && rm $0", pid);
	fclose (fp);
	chmod (diefile, 0700);
    }
    Log ("Crack v%s: The Password Cracker, (c) Alec D.E. Muffett, 1992\n",
	 version);

    /* Quick, verify that we are sane ! */

    if (strcmp (crypt ("fredfred", "fredfred"), "frxWbx4IRuBBA"))
    {
	Log ("Version of crypt() being used internally is not compatible with standard.\n");
	Log ("This could be due to byte ordering problems - see the comments in Sources/conf.h\n");
	Log ("If there is another reason for this, edit the source to remove this assertion.\n");
	Log ("Terminating...\n");
	exit (0);
    }
#ifndef AMIGA
    signal (SIGTERM, CatchTERM);
#endif

    Log ("Loading Data, host=%s pid=%d\n", this_hostname, pid);

    if (LoadData () <= 0)
    {
	Log ("Nothing to Crack. Exiting...\n");
	exit (0);
    }
    if (LoadRules (rulefile, &ruleroot) < 0 ||
	LoadRules (gecosfile, &gecosroot) < 0)
    {
	exit (1);
    }
    if (!recover_bool)
    {
	/* We are starting afresh ! Ah, the birds in May ! */
	Pass1 ();

	if (!FeedBack (0))
	{
	    Log ("FeedBack: information: all users are cracked after gecos pass\n");
	    goto finish_crack;
	}
    } else
    {
	int rval;

	if (rval = GetPoint (recover_file))
	{
	    Log ("Recovery from file %s not permitted on this host [code %d]\n",
		 recover_file,
		 rval);
	    exit (0);

	}
	/* Some spodulous creep pulled our plug... */
	while ((optind < argc) && strcmp (argv[optind], old_dictname))
	{
	    optind++;
	}
    }

    for (i = optind; i < argc; i++)
    {
	Pass2 (argv[i]);
    }

    Log ("Tidying up files...\n");
    FeedBack (1);

  finish_crack:

    if (die_bool)
    {
	unlink (diefile);
    }
    unlink (pointfile);

    Log ("Done.\n");

    return (0);
}

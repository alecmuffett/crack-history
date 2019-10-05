/*
 * This program is copyright Alec Muffett 1991 except for some portions of
 * code in "crack-fcrypt.c" which are copyright Robert Baldwin, Icarus Sparry
 * and Alec Muffett.  The author(s) disclaims all responsibility or liability
 * with respect to it's usage or its effect upon hardware or computer
 * systems, and maintain copyright as set out in the "LICENCE" document which
 * accompanies distributions of Crack v4.0 and upwards.
 */

#include <stdio.h>
#include <ctype.h>
#include <pwd.h>
#include <signal.h>

#include "conf.h"

#define STRINGSIZE	256

#ifdef DEVELOPMENT_VERSION
#define BUILTIN_CLEAR
#undef BRAINDEAD6
#define CRACK_UNAME
#endif

/* ------------------------------------------------------------------ */

#define STRCMP(x,y)		( *(x) == *(y) ? strcmp((x),(y)) : -1 )


#ifdef FAST_TOCASE
#define CRACK_TOUPPER(x)	(toupper(x))
#define CRACK_TOLOWER(x)	(tolower(x))
#else
#define CRACK_TOUPPER(x)	(islower(x) ? toupper(x) : (x))
#define CRACK_TOLOWER(x)	(isupper(x) ? tolower(x) : (x))
#endif

#ifdef INDEX_NOT_STRCHR
#define strrchr                 rindex
#define strchr 		        index
#endif

#ifndef BSD_MEMFUNC
#define bcopy(s1,s2,l)          memcpy(s2,s1,l)
#define bcmp(s1,s2,l)           memcmp(s2,s1,l)
#define bzero(s1,l)             memset(s1,'\0',l)
#endif 

/* ------------------------------------------------------------------ */

struct USER
{
    struct USER *next;		/* next users with different salt */
    struct USER *across;	/* line of users with same salt */
    char *filename;		/* where we got it from */
    char *passwd_txt;		/* plaintext of password */
    struct passwd passwd;	/* ...guess... */
    int done;			/* bool flag */
};

struct DICT
{
    struct DICT *next;		/* simple linked list */
    char word[1];		/* ...<snigger>... */
};

/* include lyrics of "perfect circle" by R.E.M. at this point */

struct RULE
{
    struct RULE *next;
    char *rule;
};

/* ------------------------------------------------------------------ */

extern void Trim ();
extern char *Reverse ();
extern char *Uppercase ();
extern char *Lowercase ();
extern char *Clone ();
extern char *Mangle ();
extern int gethostname ();

#include "crack-glob.h"

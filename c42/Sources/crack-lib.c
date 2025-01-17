/*
 * This program is copyright Alec Muffett 1991 except for some portions of
 * code in "crack-fcrypt.c" which are copyright Robert Baldwin, Icarus Sparry
 * and Alec Muffett.  The author(s) disclaims all responsibility or liability
 * with respect to it's usage or its effect upon hardware or computer
 * systems, and maintain copyright as set out in the "LICENCE" document which
 * accompanies distributions of Crack v4.0 and upwards.
 */

#include "crack.h"

#define RULE_NOOP	':'
#define RULE_PREPEND	'^'
#define RULE_APPEND	'$'
#define RULE_REVERSE	'r'
#define RULE_UPPERCASE	'u'
#define RULE_LOWERCASE	'l'
#define RULE_PLURALISE	'p'
#define RULE_CAPITALISE	'c'
#define RULE_DUPLICATE	'd'
#define RULE_REFLECT	'f'
#define RULE_SUBSTITUTE	's'
#define RULE_MATCH	'/'
#define RULE_NOT	'!'
#define RULE_LT		'<'
#define RULE_GT		'>'
#define RULE_EXTRACT	'x'
#define RULE_OVERSTRIKE	'o'
#define RULE_INSERT	'i'
#define RULE_EQUALS	'='
#define RULE_PURGE	'@'
#define RULE_CLASS	'?'	/* class rule? socialist ethic in cracker? */

void
Trim (string)			/* remove trailing whitespace from a string */
    register char *string;
{
    register char *ptr;

    for (ptr = string; *ptr; ptr++);
    while ((--ptr >= string) && isspace (*ptr));
    *(++ptr) = '\0';
}

char *
Clone (string)
    char *string;
{
    register char *retval;

    retval = (char *) malloc (strlen (string) + 1);
    if (retval)
    {
	strcpy (retval, string);
    }
    return (retval);
}

int
Suffix (word, suffix)
    char *word;
    char *suffix;
{
    register int i;
    register int j;

    i = strlen (word);
    j = strlen (suffix);

    if (i > j)
    {
	return (STRCMP ((word + i - j), suffix));
    } else
    {
	return (-1);
    }
}

char *
Reverse (str)			/* return a pointer to a reversal */
    register char *str;
{
    register int i;
    register int j;
    static char area[STRINGSIZE];

    j = i = strlen (str);
    while (*str)
    {
	area[--i] = *str++;
    }
    area[j] = '\0';
    return (area);
}

char *
Uppercase (str)			/* return a pointer to an uppercase */
    register char *str;
{
    register char *ptr;
    static char area[STRINGSIZE];

    ptr = area;
    while (*str)
    {
	*(ptr++) = CRACK_TOUPPER (*str);
	str++;
    }
    *ptr = '\0';

    return (area);
}

char *
Lowercase (str)			/* return a pointer to an lowercase */
    register char *str;
{
    register char *ptr;
    static char area[STRINGSIZE];

    ptr = area;
    while (*str)
    {
	*(ptr++) = CRACK_TOLOWER (*str);
	str++;
    }
    *ptr = '\0';

    return (area);
}

char *
Capitalise (str)		/* return a pointer to an capitalised */
    register char *str;
{
    register char *ptr;
    static char area[STRINGSIZE];

    ptr = area;

    while (*str)
    {
	*(ptr++) = CRACK_TOLOWER (*str);
	str++;
    }

    *ptr = '\0';
    area[0] = CRACK_TOUPPER (area[0]);
    return (area);
}

char *
Pluralise (string)		/* returns a pointer to a plural */
    register char *string;
{
    register int length;
    static char area[STRINGSIZE];

    length = strlen (string);
    strcpy (area, string);

    if (!Suffix (string, "ch") ||
	!Suffix (string, "ex") ||
	!Suffix (string, "ix") ||
	!Suffix (string, "sh") ||
	!Suffix (string, "ss"))
    {
	/* bench -> benches */
	strcat (area, "es");
    } else if (length > 2 && string[length - 1] == 'y')
    {
	if (strchr ("aeiou", string[length - 2]))
	{
	    /* alloy -> alloys */
	    strcat (area, "s");
	} else
	{
	    /* gully -> gullies */
	    strcpy (area + length - 1, "ies");
	}
    } else if (string[length - 1] == 's')
    {
	/* bias -> biases */
	strcat (area, "es");
    } else
    {
	/* catchall */
	strcat (area, "s");
    }

    return (area);
}

char *
Substitute (string, old, new)	/* returns pointer to a swapped about copy */
    register char *string;
    register char old;
    register char new;
{
    register char *ptr;
    static char area[STRINGSIZE];

    ptr = area;
    while (*string)
    {
	*(ptr++) = (*string == old ? new : *string);
	string++;
    }
    *ptr = '\0';
    return (area);
}

char *
Purge (string, target)		/* returns pointer to a purged copy */
    register char *string;
    register char target;
{
    register char *ptr;
    static char area[STRINGSIZE];

    ptr = area;
    while (*string)
    {
	if (*string != target)
	{
	    *(ptr++) = *string;
	}
	string++;
    }
    *ptr = '\0';
    return (area);
}
/* -------- CHARACTER CLASSES START HERE -------- */

/*
 * this function takes two inputs, a class identifier and a character, and
 * returns non-null if the given character is a member of the class, based
 * upon restrictions set out below
 */

int
MatchClass (class, input)
    register char class;
    register char input;
{
    register char c;
    register int retval;

    retval = 0;

    switch (class)
    {
	/* ESCAPE */

    case '?':			/* ?? -> ? */
	if (input == '?')
	{
	    retval = 1;
	}
	break;

	/* ILLOGICAL GROUPINGS (ie: not in ctype.h) */

    case 'V':
    case 'v':			/* vowels */
	c = CRACK_TOLOWER (input);
	if (strchr ("aeiou", c))
	{
	    retval = 1;
	}
	break;

    case 'C':
    case 'c':			/* consonants */
	c = CRACK_TOLOWER (input);
	if (strchr ("bcdfghjklmnpqrstvwxyz", c))
	{
	    retval = 1;
	}
	break;

    case 'W':
    case 'w':			/* whitespace */
	if (strchr ("\t ", input))
	{
	    retval = 1;
	}
	break;

    case 'P':
    case 'p':			/* punctuation */
	if (strchr (".`,:;'!?\"", input))
	{
	    retval = 1;
	}
	break;

    case 'S':
    case 's':			/* symbols */
	if (strchr ("$%%^&*()-_+=|\\[]{}#@/~", input))
	{
	    retval = 1;
	}
	break;

	/* LOGICAL GROUPINGS */

    case 'L':
    case 'l':			/* lowercase */
	if (islower (input))
	{
	    retval = 1;
	}
	break;

    case 'U':
    case 'u':			/* uppercase */
	if (isupper (input))
	{
	    retval = 1;
	}
	break;

    case 'A':
    case 'a':			/* alphabetic */
	if (isalpha (input))
	{
	    retval = 1;
	}
	break;

    case 'X':
    case 'x':			/* alphanumeric */
	if (isalnum (input))
	{
	    retval = 1;
	}
	break;

    case 'D':
    case 'd':			/* digits */
	if (isdigit (input))
	{
	    retval = 1;
	}
	break;

    default:
	Log ("MatchClass: unknown class %c\n", class);
	return (0);
	break;
    }

    if (isupper (class))
    {
	return (!retval);
    }
    return (retval);
}

char *
PolyStrchr (string, class)
    register char *string;
    register char class;
{
    while (*string)
    {
	if (MatchClass (class, *string))
	{
	    return (string);
	}
	string++;
    }
    return ((char *) 0);
}

char *
PolySubst (string, class, new)	/* returns pointer to a swapped about copy */
    register char *string;
    register char class;
    register char new;
{
    register char *ptr;
    static char area[STRINGSIZE];

    ptr = area;
    while (*string)
    {
	*(ptr++) = (MatchClass (class, *string) ? new : *string);
	string++;
    }
    *ptr = '\0';
    return (area);
}

char *
PolyPurge (string, class)	/* returns pointer to a purged copy */
    register char *string;
    register char class;
{
    register char *ptr;
    static char area[STRINGSIZE];

    ptr = area;
    while (*string)
    {
	if (!MatchClass (class, *string))
	{
	    *(ptr++) = *string;
	}
	string++;
    }
    *ptr = '\0';
    return (area);
}
/* -------- BACK TO NORMALITY -------- */

int
Char2Int (character)
    char character;
{
    if (isdigit (character))
    {
	return (character - '0');
    } else if (islower (character))
    {
	return (character - 'a' + 10);
    } else if (isupper (character))
    {
	return (character - 'A' + 10);
    }
    return (-1);
}

char *
Mangle (input, control)		/* returns a pointer to a controlled Mangle */
    char *input;
    char *control;
{
    int limit;
    register char *ptr;
    static char area[STRINGSIZE];
    char area2[STRINGSIZE];

    area[0] = '\0';
    strcpy (area, input);

    for (ptr = control; *ptr; ptr++)
    {
	switch (*ptr)
	{
	case RULE_NOOP:
	    break;
	case RULE_REVERSE:
	    strcpy (area, Reverse (area));
	    break;
	case RULE_UPPERCASE:
	    strcpy (area, Uppercase (area));
	    break;
	case RULE_LOWERCASE:
	    strcpy (area, Lowercase (area));
	    break;
	case RULE_CAPITALISE:
	    strcpy (area, Capitalise (area));
	    break;
	case RULE_PLURALISE:
	    strcpy (area, Pluralise (area));
	    break;
	case RULE_REFLECT:
	    strcat (area, Reverse (area));
	    break;
	case RULE_DUPLICATE:
	    strcpy (area2, area);
	    strcat (area, area2);
	    break;
	case RULE_GT:
	    if (!ptr[1])
	    {
		Log ("Mangle: '>' missing argument in '%s'\n", control);
		return ((char *) 0);
	    } else
	    {
		limit = Char2Int (*(++ptr));
		if (limit < 0)
		{
		    Log ("Mangle: '>' weird argument in '%s'\n", control);
		    return ((char *) 0);
		}
		if (strlen (area) <= limit)
		{
		    return ((char *) 0);
		}
	    }
	    break;
	case RULE_LT:
	    if (!ptr[1])
	    {
		Log ("Mangle: '<' missing argument in '%s'\n", control);
		return ((char *) 0);
	    } else
	    {
		limit = Char2Int (*(++ptr));
		if (limit < 0)
		{
		    Log ("Mangle: '<' weird argument in '%s'\n", control);
		    return ((char *) 0);
		}
		if (strlen (area) >= limit)
		{
		    return ((char *) 0);
		}
	    }
	    break;
	case RULE_PREPEND:
	    if (!ptr[1])
	    {
		Log ("Mangle: prepend missing argument in '%s'\n", control);
		return ((char *) 0);
	    } else
	    {
		area2[0] = *(++ptr);
		strcpy (area2 + 1, area);
		strcpy (area, area2);
	    }
	    break;
	case RULE_APPEND:
	    if (!ptr[1])
	    {
		Log ("Mangle: append missing argument in '%s'\n", control);
		return ((char *) 0);
	    } else
	    {
		register char *string;

		string = area;
		while (*(string++));
		string[-1] = *(++ptr);
		*string = '\0';
	    }
	    break;
	case RULE_EXTRACT:
	    if (!ptr[1] || !ptr[2])
	    {
		Log ("Mangle: extract missing argument in '%s'\n", control);
		return ((char *) 0);
	    } else
	    {
		register int i;
		int start;
		int length;

		start = Char2Int (*(++ptr));
		length = Char2Int (*(++ptr));
		if (start < 0 || length < 0)
		{
		    Log ("Mangle: extract: weird argument in '%s'\n", control);
		    return ((char *) 0);
		}
		strcpy (area2, area);
		for (i = 0; length-- && area2[start + i]; i++)
		{
		    area[i] = area2[start + i];
		}
		/* cant use strncpy() - no trailing NUL */
		area[i] = '\0';
	    }
	    break;
	case RULE_OVERSTRIKE:
	    if (!ptr[1] || !ptr[2])
	    {
		Log ("Mangle: overstrike missing argument in '%s'\n", control);
		return ((char *) 0);
	    } else
	    {
		register int i;

		i = Char2Int (*(++ptr));
		if (i < 0)
		{
		    Log ("Mangle: overstrike weird argument in '%s'\n",
			 control);
		    return ((char *) 0);
		} else
		{
		    ++ptr;
		    if (area[i])
		    {
			area[i] = *ptr;
		    }
		}
	    }
	    break;
	case RULE_INSERT:
	    if (!ptr[1] || !ptr[2])
	    {
		Log ("Mangle: insert missing argument in '%s'\n", control);
		return ((char *) 0);
	    } else
	    {
		register int i;
		register char *p1;
		register char *p2;

		i = Char2Int (*(++ptr));
		if (i < 0)
		{
		    Log ("Mangle: insert weird argument in '%s'\n",
			 control);
		    return ((char *) 0);
		}
		p1 = area;
		p2 = area2;
		while (i && *p1)
		{
		    i--;
		    *(p2++) = *(p1++);
		}
		*(p2++) = *(++ptr);
		strcpy (p2, p1);
		strcpy (area, area2);
	    }
	    break;
	    /* THE FOLLOWING RULES REQUIRE CLASS MATCHING */

	case RULE_PURGE:	/* @x or @?c */
	    if (!ptr[1] || (ptr[1] == RULE_CLASS && !ptr[2]))
	    {
		Log ("Mangle: delete missing arguments in '%s'\n", control);
		return ((char *) 0);
	    } else if (ptr[1] != RULE_CLASS)
	    {
		strcpy (area, Purge (area, *(++ptr)));
	    } else
	    {
		strcpy (area, PolyPurge (area, ptr[2]));
		ptr += 2;
	    }
	    break;
	case RULE_SUBSTITUTE:	/* sxy || s?cy */
	    if (!ptr[1] || !ptr[2] || (ptr[1] == RULE_CLASS && !ptr[3]))
	    {
		Log ("Mangle: subst missing argument in '%s'\n", control);
		return ((char *) 0);
	    } else if (ptr[1] != RULE_CLASS)
	    {
		strcpy (area, Substitute (area, ptr[1], ptr[2]));
		ptr += 2;
	    } else
	    {
		strcpy (area, PolySubst (area, ptr[2], ptr[3]));
		ptr += 3;
	    }
	    break;
	case RULE_MATCH:	/* /x || /?c */
	    if (!ptr[1] || (ptr[1] == RULE_CLASS && !ptr[2]))
	    {
		Log ("Mangle: '/' missing argument in '%s'\n", control);
		return ((char *) 0);
	    } else if (ptr[1] != RULE_CLASS)
	    {
		if (!strchr (area, *(++ptr)))
		{
		    return ((char *) 0);
		}
	    } else
	    {
		if (!PolyStrchr (area, ptr[2]))
		{
		    return ((char *) 0);
		}
		ptr += 2;
	    }
	    break;
	case RULE_NOT:		/* !x || !?c */
	    if (!ptr[1] || (ptr[1] == RULE_CLASS && !ptr[2]))
	    {
		Log ("Mangle: '!' missing argument in '%s'\n", control);
		return ((char *) 0);
	    } else if (ptr[1] != RULE_CLASS)
	    {
		if (strchr (area, *(++ptr)))
		{
		    return ((char *) 0);
		}
	    } else
	    {
		if (PolyStrchr (area, ptr[2]))
		{
		    return ((char *) 0);
		}
		ptr += 2;
	    }
	    break;

	    /*
	     * alternative use for a boomerang, number 1: a standard throwing
	     * boomerang is an ideal thing to use to tuck the sheets under
	     * the mattress when making your bed.  The streamlined shape of
	     * the boomerang allows it to slip easily 'twixt mattress and
	     * bedframe, and it's curve makes it very easy to hook sheets
	     * into the gap.
	     */

	case RULE_EQUALS:	/* =nx || =n?c */
	    if (!ptr[1] || !ptr[2] || (ptr[2] == RULE_CLASS && !ptr[3]))
	    {
		Log ("Mangle: '=' missing argument in '%s'\n", control);
		return ((char *) 0);
	    } else
	    {
		register int i;

		if ((i = Char2Int (ptr[1])) < 0)
		{
		    Log ("Mangle: '=' weird argument in '%s'\n", control);
		    return ((char *) 0);
		}
		if (ptr[2] != RULE_CLASS)
		{
		    ptr += 2;
		    if (area[i] != *ptr)
		    {
			return ((char *) 0);
		    }
		} else
		{
		    ptr += 3;
		    if (!MatchClass (*ptr, area[i]))
		    {
			return ((char *) 0);
		    }
		}
	    }
	    break;
	default:
	    Log ("Mangle: unknown command %c in %s\n", *ptr, control);
	    return ((char *) 0);
	    break;
	}
    }
    if (!area[0])		/* have we deweted de poor widdle fing away? */
    {
	return ((char *) 0);
    }
    return (area);
}

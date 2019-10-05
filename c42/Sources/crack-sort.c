#include "crack.h"
#define Compare(a,b) 	(strcmp(a,b))

/*
 * Sort a list of struct DICT by using an iterative bottom-up merge sort.
 * This particular piece of code took me ages to do (well, 2 days + 3 weeks
 * research) and provides a FAST way of sorting a linked list without the
 * overhead of increasing memory usage via malloc() or brk(). Why ? Because I
 * have to assume that there is no more memory, thats why. It's all Brian
 * Thompsett's fault! Really! Filling the swapspace on a SparcStation2 and
 * expecting Crack to survive! Argh! 8-)
 */

/* Since this code is so nice, I'll comment it fairly thoroughly */

struct DICT *
SortDict (chain3, listlength)
    register struct DICT *chain3;
    long int listlength;
{
    /* misc counters */
    register int i;
    long int discarded;

    /* 2^n for n = 0..x */
    long int n;

    /* head of the first extracted subchain */
    register struct DICT *chain1;

    /* head of second subchain */
    register struct DICT *chain2;

    /* useful temp pointer */
    register struct DICT *scratch;

    /* PTR TO ELEMENT containing TAIL of unsorted list pre-merging */
    struct DICT *lead_in;

    /* PTR TO HEAD of unsorted list after extracting chains */
    struct DICT *lead_out;

    /* dummy structures used as fenceposts */
    struct DICT dummy1;
    struct DICT dummy2;

    /* Put the incoming list into 'dummy1' posthole */
    dummy1.next = chain3;

    /* For values of n = 2^(0..30) limited by listlength */
    for (n = 1L; n < listlength; n *= 2)
    {
	/* Store place to get/put head of list in 'lead_in' */
	lead_in = &dummy1;

	/* Set chain1 to the head of unsorted list */
	for (chain1 = lead_in -> next; chain1; chain1 = lead_in -> next)
	{
	    /* Break connection head and chain1 */
	    lead_in -> next = (struct DICT *) 0;

	    /* Extract up to length 'n', park on last element before chain2 */
	    for (i = n - 1, scratch = chain1;
		 i && scratch -> next;
		 scratch = scratch -> next)
	    {
		i--;
	    };

	    /* If chain1 is undersized/exact, there is no chain2 */
	    if (i || !scratch -> next)
	    {
		/* put chain1 back where you got it and break */
		lead_in -> next = chain1;
		break;
	    }
	    /* Get pointer to head of chain2 */
	    chain2 = scratch -> next;

	    /* Break connection between chain1 & chain2 */
	    scratch -> next = (struct DICT *) 0;

	    /* Extract up to length 'n', park on last element of chain2 */
	    for (i = n - 1, scratch = chain2;
		 i && scratch -> next;
		 scratch = scratch -> next)
	    {
		i--;
	    };

	    /* Even if it's NULL, store rest of list in 'lead_out' */
	    lead_out = scratch -> next;

	    /* Break connection between chain2 & tail of unsorted list */
	    scratch -> next = (struct DICT *) 0;

	    /* Now, mergesort chain1 & chain2 to chain3 */

	    /* Set up dummy list fencepost */
	    chain3 = &dummy2;
	    chain3 -> next = (struct DICT *) 0;

	    /* While there is something in each list */
	    while (chain1 && chain2)
	    {
		/* Compare them */
		i = Compare (chain1 -> word, chain2 -> word);

		if (i < 0)
		{
		    /* a < b */
		    chain3 -> next = chain1;
		    chain3 = chain1;
		    chain1 = chain1 -> next;
		} else if (i > 0)
		{
		    /* a > b */
		    chain3 -> next = chain2;
		    chain3 = chain2;
		    chain2 = chain2 -> next;
		} else
		{
		    /*
		     * a == b. Link them both in. Don't try to get rid of the
		     * multiple copies here, because if you free up any
		     * elements at this point the listsize changes and the
		     * algorithm runs amok.
		     */
		    chain3 -> next = chain1;
		    chain3 = chain1;
		    chain1 = chain1 -> next;
		    chain3 -> next = chain2;
		    chain3 = chain2;
		    chain2 = chain2 -> next;
		}
	    }

	    /*
	     * Whatever is left is sorted and therefore linkable straight
	     * onto the end of the current list.
	     */

	    if (chain1)
	    {
		chain3 -> next = chain1;
	    } else
	    {
		chain3 -> next = chain2;
	    }

	    /* Skip to the end of the sorted list */
	    while (chain3 -> next)
	    {
		chain3 = chain3 -> next;
	    }

	    /* Append this lot to where you got chain1 from ('lead_in') */
	    lead_in -> next = dummy2.next;

	    /* Append rest of unsorted list to chain3 */
	    chain3 -> next = lead_out;

	    /* Set 'lead_in' for next time to last element of 'chain3' */
	    lead_in = chain3;
	}
    }

    /* Now, Uniq the list */
    discarded = 0;

    /* Chain1 to the head of the list, Chain2 to the next */
    chain1 = dummy1.next;
    chain2 = chain1 -> next;

    /* While not at end of list */
    while (chain2)
    {
	/* Whilst (chain1) == (chain2) */
	while (!Compare (chain1 -> word, chain2 -> word))
	{
	    /* Bump the discard count */
	    discarded++;

	    /* Store the next element */
	    scratch = chain2 -> next;

	    /* Get some memory back */
	    free (chain2);	/* ...<snigger>... */

	    /* Assign the skip, break if you run off the end of list */
	    if (!(chain2 = scratch))
	    {
		break;
	    }
	}

	/* Set comparison ptr to new element or terminate */
	chain1 -> next = chain2;

	/* If not terminated */
	if (chain2)
	{
	    /* set the compared pointer to its successor */
	    chain1 = chain2;
	    chain2 = chain2 -> next;
	}
    }

    Log ("Sort discarded %ld words; FINAL DICTIONARY SIZE: %ld\n",
	 discarded,
	 listlength - discarded);

    return (dummy1.next);
}

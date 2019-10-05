#include "crack.h"

char version[] = "4.1f";	/* version of prog */
char runtime[] = "Runtime";
char feedback_string[] = "!fb!";
char rulefile[] = "Scripts/dicts.rules";
char gecosfile[] = "Scripts/gecos.rules";
char nastygram[] = "Scripts/nastygram";
char smartcat[] =  "Scripts/smartcat";
char pauser[] =  "Scripts/pauser";


/* runtime variable declarations */

int pid;			/* current process ID */
int pwlength = 8;		/* significant length of a password */
struct USER *userroot;		/* root of linked list of users */
struct RULE *ruleroot;		/* root of linked list of rules */
struct RULE *gecosroot;		/* root of linked list of (gecos) rules */
struct DICT *dictroot;		/* root of linked list of words */

/* datafile variables */

char diefile[STRINGSIZE];	/* where die output goes... */
char feedbackfile[STRINGSIZE];	/* where feedback ouytput goes */
char opfile[STRINGSIZE];	/* where Log() output goes */
char pointfile[STRINGSIZE];	/* checkpointing */
char this_hostname[STRINGSIZE];	/* gethostname() hack */

/* recover variables */

char old_hostname[STRINGSIZE];	/* next 4 vars used in recovery */
char old_dictname[STRINGSIZE];
char old_rule[STRINGSIZE];
int old_usernum;
char old_username[STRINGSIZE];

/* switches */
char input_file[STRINGSIZE];
int foreground_bool;
int remote_bool;
int nice_value;
int recover_bool;
char recover_file[STRINGSIZE];
int verbose_bool;
char supplied_name[STRINGSIZE];
int mail_bool;

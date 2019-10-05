extern char version[];
extern char runtime[];
extern char feedback_string[];
extern char rulefile[];
extern char gecosfile[];
extern char nastygram[];
extern char smartcat[];
extern char pauser[];
extern int pid;
extern int pwlength;
extern struct USER *userroot;
extern struct RULE *ruleroot;
extern struct RULE *gecosroot;
extern struct DICT *dictroot;
extern char diefile[STRINGSIZE];
extern char feedbackfile[STRINGSIZE];
extern char opfile[STRINGSIZE];
extern char pointfile[STRINGSIZE];
extern char this_hostname[STRINGSIZE];
extern char old_hostname[STRINGSIZE];
extern char old_dictname[STRINGSIZE];
extern char old_rule[STRINGSIZE];
extern int old_usernum;
extern char old_username[STRINGSIZE];
extern char input_file[STRINGSIZE];
extern int foreground_bool;
extern int remote_bool;
extern int nice_value;
extern int recover_bool;
extern char recover_file[STRINGSIZE];
extern int verbose_bool;
extern char supplied_name[STRINGSIZE];
extern int mail_bool;

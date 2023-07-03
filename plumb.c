#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
#include <err.h>
#include <limits.h>
#include <regex.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <magic.h>

#define LEN(a)          (sizeof(a) / sizeof((a)[0]))
#define ENVVAR_MAX      128
#define MAXTOKENS       128
#define RULESPATH       "/lib/plumb"
#define HOME            "HOME"
#define OPEN_ACTION     "open"
#define EDIT_ACTION     "edit"
#define DEF_ACTION      OPEN_ACTION
#define ALPHANUM        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"

struct Variable {
	struct Variable *next;
	char *name;
	char *value;
} *globals, *locals;

struct Argument {
	struct Variable *globals, *locals;
	char *data;
};

struct Ruleset {
	/*
	 * Each block of rule, initiated by a "rules for <RULESET_NAME>"
	 * line on the config file, is a ruleset.  A ruleset is made of
	 * its name (as an array of arguments) and a list of rules.
	 *
	 * Each rule represents a line in the config file with the form
	 * "<SUBJ> <TYPE> <ARGS>".  <SUBJ> is a string that dictates the
	 * rule's subject; <TYPE> is the string "matches", "types" or
	 * "with"; and <ARGS> is an array of argument strings.
	 *
	 * A rule of type "matches" has a special argument.  Its first
	 * argument is a regular expression, while the following
	 * optional arguments are strings.
	 */
	struct Ruleset *next;
	struct Rule {
		struct Ruleset *set;
		struct Rule *next;
		char *subj;
		enum Type {
			RULE_MATCHES,
			RULE_TYPES,
			RULE_WITH,
		} type;
		regex_t reg;            /* only used in "matches" rules */
		char **argv;
		size_t argc;
	} *rules;
	char **argv;
	size_t argc;
};

struct Parsectx {
	/*
	 * Context for parsing the config file.
	 */
	FILE *fp;
	char *filename;
	size_t lineno;
	bool goterror;
};

extern char **environ;

static magic_t magic;

static void
usage(void)
{
	(void)fprintf(stderr, "usage: plumb [-actions] arg...\n");
	exit(EXIT_FAILURE);
}

static void *
erealloc(void *p, size_t size)
{
	if ((p = realloc(p, size)) == NULL)
		err(EXIT_FAILURE, "realloc");
	return p;
}

static void *
ecalloc(size_t nmemb, size_t size)
{
	void *p;

	if ((p = calloc(nmemb, size)) == NULL)
		err(EXIT_FAILURE, "calloc");
	return p;
}

static void *
emalloc(size_t size)
{
	void *p;

	if ((p = malloc(size)) == NULL)
		err(EXIT_FAILURE, "malloc");
	return p;
}

static char *
estrdup(const char *s)
{
	char *p;

	if ((p = strdup(s)) == NULL)
		err(EXIT_FAILURE, "strdup");
	return p;
}

static char *
estrndup(const char *s, size_t maxlen)
{
	char *p;

	if ((p = strndup(s, maxlen)) == NULL)
		err(EXIT_FAILURE, "strndup");
	return p;
}

static pid_t
efork(void)
{
	pid_t pid;

	if ((pid = fork()) < 0)
		err(EXIT_FAILURE, "fork");
	return pid;
}

static int
beginsruleset(char **toks, size_t ntoks)
{
	return ntoks > 2 &&
		strcmp(toks[0], "rules") == 0 &&
		strcmp(toks[1], "for") == 0;
}

static void
syntaxerr(struct Parsectx *parse, const char *msg, const char *arg)
{
	if (arg == NULL) {
		warnx(
			"%s:%zu: syntax error: %s",
			parse->filename,
			parse->lineno,
			msg
		);
	} else {
		warnx(
			"%s:%zu: syntax error: %s \"%s\"",
			parse->filename,
			parse->lineno,
			msg,
			arg
		);
	}
	parse->goterror = true;
}

static struct Rule *
newrule(struct Parsectx *parse, char *toks[], size_t ntoks)
{
	struct Rule *rule;
	regex_t reg;
	size_t i, n;
	int flags, res;
	enum Type type;
	char errbuf[1024];

	assert(ntoks > 2);      /* we handle ntoks <= 2 before */
	flags = REG_EXTENDED;
	if (strcmp(toks[1], "matches") == 0) {
		type = RULE_MATCHES;
	} else if (strcmp(toks[1], "imatches") == 0) {
		flags |= REG_ICASE;
		type = RULE_MATCHES;
	} else if (strcmp(toks[1], "types") == 0) {
		type = RULE_TYPES;
	} else if (strcmp(toks[1], "with") == 0) {
		type = RULE_WITH;
	} else {
		syntaxerr(parse, "unknown predicate", toks[1]);
		return NULL;
	}
	memset(&reg, 0, sizeof(reg));
	n = 2;
	switch (type) {
	case RULE_MATCHES:
		n++;
		if (ntoks > 3) {
			if (strcmp(toks[3], "into") != 0) {
				syntaxerr(parse, "unknown argument", toks[3]);
				return NULL;
			}
			n++;
		}
		if ((res = regcomp(&reg, toks[2], flags)) != 0) {
			if (regerror(res, &reg, errbuf, sizeof(errbuf)) > 0)
				syntaxerr(parse, errbuf, NULL);
			else
				syntaxerr(parse, "wrong regex", toks[2]);
			regfree(&reg);
			return NULL;
		}
		break;
	case RULE_TYPES:
		if (ntoks != 3) {
			syntaxerr(parse, "improper \"types\" rule", NULL);
			return NULL;
		}
		break;
	case RULE_WITH:
		/* we deal with this later */
		break;
	}
	rule = emalloc(sizeof(*rule));
	*rule = (struct Rule){
		.set = NULL,
		.type = type,
		.reg = reg,
		.argv = NULL,
		.argc = 0,
		.subj = toks[0],
	};
	if (n < ntoks) {
		rule->argc = ntoks - n;
		rule->argv = ecalloc(rule->argc, sizeof(*rule->argv));
		memcpy(rule->argv, toks + n, rule->argc * sizeof(*rule->argv));
	}
	for (i = 1; i < n; i++)
		free(toks[i]);
	return rule;
}

static void
insertvar(struct Variable **head, char *name, char *value)
{
	struct Variable *var;

	if (name == NULL) {
		free(value);
		return;
	}
	for (var = *head; var != NULL; var = var->next) {
		if (strcmp(var->name, name) == 0) {
			free(var->value);
			var->value = value;
			return;
		}
	}
	var = emalloc(sizeof(*var));
	*var = (struct Variable){
		.name = name,
		.value = value,
	};
	var->next = *head;
	*head = var;
}

static char *
lookupvar(struct Variable *var, const char *name)
{
	if (name == NULL)
		return NULL;
	for ( ; var != NULL; var = var->next)
		if (strcmp(var->name, name) == 0)
			return var->value != NULL ? var->value : "";
	return getenv(name);
}

static size_t
strnrspn(char *buf, char *charset, size_t len)
{
	while (len > 0 && strchr(charset, buf[len - 1]) != NULL)
		len--;
	return len;
}

static size_t
tokenize(struct Parsectx *parse, struct Variable *env,
         char *str, char *toks[], size_t maxtoks)
{
	char *buf, *val;
	size_t ntoks, bufsize, len;
	size_t j, k;
	char c;
	bool inquote = false;

	ntoks = 0;
	bufsize = 0;
	buf = NULL;
	while (*str != '\0' && ntoks < maxtoks) {
		str += strspn(str, " \t");
		j = 0;
		while (*str != '\0') {
			if (!inquote && strchr(" \t", *str))
				break;
			val = NULL;
			if (!inquote && str[0] == '$' && str[1] == '{') {
				/* ${VARIABLE} */
				str += 2;
				k = strcspn(str, "}");
				if (k == 0) {
					syntaxerr(parse, "bad substitution", "${}");
					goto error;
				}
				if (str[k] != '}') {
					syntaxerr(parse, "unmatching bracket", NULL);
					goto error;
				}
				str[k] = '\0';
				if ((val = lookupvar(env, str)) == NULL)
					val = "";
				len = strlen(val);
				str += k + 1;
			} else if (!inquote && str[0] == '$' && str[1] == '$') {
				/* $$ */
				str += 2;
				val = "$";
				len = 1;
			} else if (!inquote && str[0] == '$') {
				/* $VARIABLE */
				str++;
				k = strspn(str, ALPHANUM);
				if (k == 0) {
					syntaxerr(parse, "bad substitution", "$");
					goto error;
				}
				c = str[k];
				str[k] = '\0';
				if ((val = lookupvar(env, str)) == NULL)
					val = "";
				len = strlen(val);
				str += k;
				if (c != '\0') {
					str[0] = c;
				}
			} else if (inquote && str[0] == '\'' && str[1] == '\'') {
				/* '' */
				str += 2;
				val = "'";
				len = 1;
			} else if (str[0] == '\'') {
				/* ' */
				inquote = !inquote;
				str++;
				continue;
			} else {
				/* char */
				val = str;
				len = 1;
				str++;
			}
			if (j + len + 1 > bufsize) {
				bufsize += len + 128;
				buf = erealloc(buf, bufsize);
			}
			memcpy(buf + j, val, len);
			j += len;
		}
		if (buf == NULL)
			return 0;
		buf[j] = '\0';
		toks[ntoks++] = estrdup(buf);
	}
	free(buf);
	return ntoks;
error:
	free(buf);
	for (j = 0; j < ntoks; j++)
		free(toks[j]);
	return 0;
}

static void
freevars(struct Variable *head, bool freename)
{
	struct Variable *tmp;

	while (head != NULL) {
		tmp = head;
		head = head->next;
		if (freename)
			free(tmp->name);
		free(tmp->value);
		free(tmp);
	}
}

static struct Ruleset *
readrules(struct Parsectx *parse)
{
	struct Rule *rule = NULL, *currule;
	struct Ruleset *head = NULL, *curset, *set;
	struct Variable *env = NULL;
	ssize_t linelen;
	size_t ntoks, n, i;
	size_t linesize = 0;
	char *toks[MAXTOKENS];
	char *line = NULL;
	char *str = NULL;

	head = curset = emalloc(sizeof(*curset));
	*curset = (struct Ruleset){ 0 };
	while ((linelen = getline(&line, &linesize, parse->fp)) != -1) {
		parse->lineno++;
		str = line;
		n = strspn(line, " \t");
		str += n;
		linelen -= n;
		str[strnrspn(line, " \t\n", linelen)] = '\0';
		if (str[0] == '\0' || str[0] == '#')
			continue;
		if ((ntoks = tokenize(parse, env, str, toks, LEN(toks))) == 0)
			continue;
		if (ntoks < 3) {
			syntaxerr(parse, "improper rule", NULL);
			goto error;
		}
		if (toks[1][0] == '=' && toks[1][1] == '\0') {
			/* variable assignment */
			if (ntoks != 3) {
				syntaxerr(parse, "bad assignment", NULL);
				goto error;
			}
			insertvar(&env, toks[0], toks[2]);
			free(toks[1]);         /* free "=" */
			continue;
		} else if (beginsruleset(toks, ntoks)) {
			/* a new ruleset begins */
			set = emalloc(sizeof(*set));
			*set = (struct Ruleset){
				.next = NULL,
				.rules = NULL,
				.argv = NULL,
				.argc = ntoks - 2,
			};
			set->argv = ecalloc(set->argc, sizeof(*set->argv));
			memcpy(set->argv, toks+2, set->argc*sizeof(*set->argv));
			free(toks[0]);          /* free "rules" */
			free(toks[1]);          /* free "for" */
			curset->next = set;
			curset = set;
		} else if ((rule = newrule(parse, toks, ntoks)) != NULL) {
			/* new rule for current ruleset */
			rule->set = curset;
			if (curset->rules == NULL)
				curset->rules = rule;
			else
				currule->next = rule;
			currule = rule;
		} else {
			syntaxerr(parse, "improper rule", NULL);
error:
			for (i = 0; i < ntoks; i++) {
				free(toks[i]);
			}
		}
	}
	freevars(env, true);
	free(line);
	return head;
}

static char *
getconfig(void)
{
	char *home, *filename;
	size_t size;

	if ((home = getenv(HOME)) == NULL)
		errx(EXIT_FAILURE, "could not find $HOME");
	size = strlen(home) + sizeof(RULESPATH);
	filename = emalloc(size);
	(void)snprintf(filename, size, "%s" RULESPATH, home);
	return filename;

}

static void
freerules(struct Ruleset *head)
{
	struct Ruleset *set;
	struct Rule *rule;
	size_t i;

	while (head != NULL) {
		set = head;
		head = set->next;
		while (set->rules != NULL) {
			rule = set->rules;
			set->rules = rule->next;
			if (rule->type == RULE_MATCHES)
				regfree(&rule->reg);
			for (i = 0; i < rule->argc; i++)
				free(rule->argv[i]);
			free(rule->argv);
			free(rule->subj);
			free(rule);
		}
		for (i = 0; i < set->argc; i++)
			free(set->argv[i]);
		free(set->argv);
		free(set);
	}
}

static char *
lookupargvar(struct Variable *globals, struct Variable *locals,
             char *data, char *name)
{
	char *value;

	value = lookupvar(locals, name);
	if (value == NULL)
		value = lookupvar(globals, name);
	if (value == NULL && strcmp("data", name) == 0)
		value = data;
	if (value == NULL)
		value = "";
	return value;
}

static struct Rule *
matchruleset(struct Ruleset *set, char *arg,
             char **actions, int nactions,
             struct Variable *globals, struct Variable **locals_ret)
{
	struct Variable *locals = NULL;
	struct Rule *rule = NULL;
	regmatch_t pmatch[MAXTOKENS];
	regoff_t beg, len;
	size_t i;
	int j;
	char *value, *newstr;
	const char *filetype;
	bool match = true;

	for (rule = set->rules; rule != NULL; rule = rule->next) {
		if (rule->type == RULE_WITH)
			continue;       /* we handle RULE_WITH later */
		value = lookupargvar(globals, locals, arg, rule->subj);
		if (rule->type == RULE_TYPES) {
			filetype = magic_file(magic, value);
			if (filetype != NULL) {
				newstr = estrdup(filetype);
				insertvar(&locals, rule->argv[0], newstr);
			} else {
				insertvar(&locals, rule->argv[0], NULL);
			}
			continue;
		}
		/* rule->type == RULE_MATCHES */
		if (regexec(&rule->reg, value, MAXTOKENS, pmatch, 0) != 0) {
			match = false;
			continue;
		}
		if (pmatch[0].rm_so != 0 || value[pmatch[0].rm_eo] != '\0') {
			match = false;
			continue;
		}
		for (i = 0; i < rule->reg.re_nsub && i < rule->argc; i++) {
			beg = pmatch[i + 1].rm_so;
			len = pmatch[i + 1].rm_eo - beg;
			if (beg >= 0 && len >= 0) {
				newstr = estrndup(value + beg, len);
				insertvar(&locals, rule->argv[i], newstr);
			} else {
				insertvar(&locals, rule->argv[i], NULL);
			}
		}
	}
	if (locals_ret != NULL)
		*locals_ret = locals;
	else
		freevars(locals, false);
	if (!match)
		return NULL;
	for (rule = set->rules; rule != NULL; rule = rule->next) {
		if (rule->type != RULE_WITH)
			continue;
		for (j = 0; j < nactions; j++) {
			if (strcmp(actions[j], rule->subj) == 0) {
				return rule;
			}
		}
	}
	return NULL;
}

static void
plumb(struct Rule *rule, struct Argument *args, int argc)
{
	char **newargv = NULL;
	char **cmd = NULL;
	char *buf = NULL;
	char *str, *var, *val;
	size_t len, k;
	size_t pos = 0;
	size_t size;
	size_t bufsize = 0;
	int newargc = 0;
	int i;
	char ch;
	bool gotvar = false;

	if (rule == NULL) {
		warnx("could not find rule for arguments");
		return;
	}
	(void)fprintf(stderr, "plumbing ");
	for (k = 0; k < rule->set->argc; k++) {
		(void)fprintf(
			stderr,
			"%s%s",
			(k == 0 ? "" : " "),
			rule->set->argv[k]
		);
	}
	(void)fprintf(stderr, "\n");
	str = rule->argv[rule->argc - 1];
	len = 0;
	var = NULL;
	while (*str != '\0') {
		if (!gotvar && str[0] == '%' && str[1] == '{') {
			/* %{VARIABLE} */
			k = strcspn(str + 2, "}");
			if (k == 0 || str[k + 2] != '}')
				goto fallback;
			str += 2;
			str[k] = '\0';
			var = str;
			str += k + 1;
			gotvar = true;
			pos = len;
			continue;
		} else if (!gotvar && str[0] == '%') {
			/* %VARIABLE */
			k = strspn(str + 1, ALPHANUM);
			if (k == 0)
				goto fallback;
			str++;
			ch = str[k];
			str[k] = '\0';
			var = str;
			str += k;
			if (ch != '\0')
				str[0] = ch;
			pos = len;
			gotvar = true;
			continue;
		} else if (!gotvar && str[0] == '%' && str[1] == '%') {
			/* %% */
			ch = '%';
			str += 2;
		} else {
fallback:
			/* char */
			ch = *str;
			str++;
		}
		if (len + 2 > bufsize) {
			bufsize += len + 128;
			buf = erealloc(buf, bufsize);
		}
		buf[len++] = ch;
	}
	if (buf != NULL) {
		buf[len] = '\0';
		str = buf;
	} else {
		str = "";
		pos = len = 0;
	}
	if (var == NULL) {
		cmd = ecalloc(rule->argc + 1, sizeof(*cmd));
		for (k = 0; k < rule->argc - 1; k++)
			cmd[k] = rule->argv[k];
		cmd[k++] = str;
		cmd[k] = NULL;
		fprintf(stderr, "UVA\n");
	} else if (var != NULL) {
		newargc = argc,
		newargv = ecalloc(newargc, sizeof(*newargv));
		for (i = 0; i < argc; i++) {
			val = lookupargvar(
				args[i].globals,
				args[i].locals,
				args[i].data,
				var
			);
			size = len + strlen(val) + 1;
			newargv[i] = emalloc(size);
			(void)snprintf(
				newargv[i],
				size,
				"%.*s%s%.*s",
				(int)pos,
				str,
				val,
				(int)(len - pos),
				str + pos
			);
		}
		cmd = ecalloc(rule->argc + newargc, sizeof(*cmd));
		for (k = 0; k < rule->argc - 1; k++)
			cmd[k] = rule->argv[k];
		for (k = 0; k < (size_t)newargc; k++)
			cmd[rule->argc - 1 + k] = newargv[k];
		cmd[rule->argc + newargc - 1] = NULL;
	}
	if (efork() == 0) {
		if (posix_spawnp(NULL, cmd[0], NULL, NULL, cmd, environ))
			err(EXIT_FAILURE, "posix_spawnp");
		exit(EXIT_SUCCESS);
	}
	free(cmd);
	free(buf);
	for (i = 0; i < newargc; i++)
		free(newargv[i]);
	free(newargv);
}

static void
freeargs(struct Argument *args, int argc)
{
	int i;

	for (i = 0; i < argc; i++) {
		freevars(args[i].globals, false);
		freevars(args[i].locals, false);
	}
	free(args);
}

int
main(int argc, char *argv[])
{
	struct Ruleset *sets, *set;
	struct Rule *plumbwith = NULL;
	struct Rule *newaction = NULL;
	struct Argument *args;
	struct Parsectx parse = { 0 };
	size_t span;
	char **actions;
	int nactions;
	int i;

	actions = &argv[1];
	nactions = 0;
	for (i = 1; i < argc; i++) {
		span = strspn(argv[i], "-");
		if (span == 0)                       /* argv[i] is not -word */
			break;
		if (argv[i][span] == '\0') {         /* argv[i] is -- */
			i++;
			break;
		}
		if (strcmp(argv[i], "-o") == 0)      /* argv[i] is -o */
			argv[i] = OPEN_ACTION;
		else if (strcmp(argv[i], "-e") == 0) /* argv[i] is -e */
			argv[i] = EDIT_ACTION;
		else                                 /* argv[i] is -word */
			argv[i]++;
		nactions++;
	}
	argc -= i;
	argv += i;
	if (argc == 0)
		usage();
	if (nactions == 0) {
		actions = (char *[]){ DEF_ACTION };
		nactions = 1;
	}
	args = ecalloc(argc, sizeof(*args));
	magic = magic_open(
		MAGIC_SYMLINK | MAGIC_MIME_TYPE |
		MAGIC_PRESERVE_ATIME | MAGIC_ERROR
	);
	if (magic == NULL)
		errx(EXIT_FAILURE, "could not get magic cookie");
	if (magic_load(magic, NULL) == -1)
		errx(EXIT_FAILURE, "could not load magic database");
	parse.filename = getconfig();
	if ((parse.fp = fopen(parse.filename, "r")) == NULL)
		err(EXIT_FAILURE, "%s", parse.filename);
	sets = readrules(&parse);
	for (i = 0; i < argc; i++) {
		/*
		 * First we run on the top ruleset, which should contain
		 * no action rule, so we can fill in the global argument
		 * variables.
		 */
		args[i].data = argv[i];
		args[i].globals = NULL;
		args[i].locals = NULL;
		set = sets;
		(void)matchruleset(
			set, argv[i],
			actions, nactions,
			NULL, &args[i].globals
		);
		if (i == 0) {
			/*
			 * For the first argument, we find a ruleset
			 * matching it.
			 */
			while ((set = set->next) != NULL) {
				plumbwith = matchruleset(
					set, argv[i],
					actions, nactions,
					args[i].globals, &args[i].locals
				);
				if (plumbwith != NULL)
					break;
				freevars(args[i].locals, false);
				args[i].locals = NULL;
			}
			if (plumbwith == NULL) {
				break;
			}
		} else {
			/*
			 * For the following arguments, we check whether
			 * the it matchs the ruleset of the 1st argument.
			 */
			newaction = matchruleset(
				plumbwith->set, argv[i],
				actions, nactions,
				args[i].globals, &args[i].locals
			);
			if (plumbwith != newaction) {
				freevars(args[i].locals, false);
				args[i].locals = NULL;
				plumbwith = NULL;
				break;
			}
		}
	}
	magic_close(magic);
	plumb(plumbwith, args, argc);
	freerules(sets);
	free(parse.filename);
	freeargs(args, argc);
	return 0;
}

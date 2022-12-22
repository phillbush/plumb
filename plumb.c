#include <sys/queue.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <err.h>
#include <ctype.h>
#include <limits.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <magic.h>

#define BUFSIZE         1024
#define ENVVAR_MAX      128
#define MAXTOKENS       128
#define RULESPATH       "lib/plumb"
#define HOME            "HOME"
#define ACTION_OPEN     "open"
#define ACTION_EDIT     "edit"

TAILQ_HEAD(FrameQueue, Frame);
TAILQ_HEAD(RuleQueue, Rule);
TAILQ_HEAD(RulesetQueue, Ruleset);

struct Frame {
	/* singly-linked list of name-value pairs */
	TAILQ_ENTRY(Frame) entries;
	char *name;
	char *value;
};

struct Arg {
	struct FrameQueue globals;
	struct FrameQueue locals;
	const char *data;
};

struct Stringa {
	/* string array */
	size_t nstrs;
	char **strs;
};

struct Rule {
	TAILQ_ENTRY(Rule) entries;
	enum {
		RULE_MATCHES,
		RULE_TYPES,
		RULE_WITH,
	} type;
	regex_t reg;
	char *subj;
	struct Stringa compls;
};

struct Ruleset {
	TAILQ_ENTRY(Ruleset) entries;
	struct RuleQueue rules;
	struct Stringa name;
};

static void
usage(void)
{
	(void)fprintf(stderr, "usage: plumb [-eon] [-a actions] [-c config] arg...\n");
	exit(1);
}

static void *
emalloc(size_t size)
{
	void *p;

	if ((p = malloc(size)) == NULL)
		err(1, "malloc");
	return p;
}

static void *
erealloc(void *p, size_t size)
{
	if ((p = realloc(p, size)) == NULL)
		err(1, "realloc");
	return p;
}

static void *
ecalloc(size_t nmemb, size_t size)
{
	void *p;
	if ((p = calloc(nmemb, size)) == NULL)
		err(1, "calloc");
	return p;
}

static char *
estrdup(const char *s)
{
	char *p;

	if ((p = strdup(s)) == NULL)
		err(1, "strdup");
	return p;
}

static char *
estrndup(const char *s, size_t maxlen)
{
	char *p;

	if ((p = strndup(s, maxlen)) == NULL)
		err(1, "strndup");
	return p;
}

static pid_t
efork(void)
{
	pid_t pid;

	if ((pid = fork()) < 0)
		err(1, "fork");
	return pid;
}

static const char *
getconfig(char *path, size_t size)
{
	char *home;

	if ((home = getenv(HOME)) == NULL)
		errx(1, "could not find $HOME");
	snprintf(path, size, "%s/%s", home, RULESPATH);
	return path;
}

static FILE *
openrules(const char *path)
{
	FILE *fp;

	if ((fp = fopen(path, "r")) == NULL)
		err(1, "%s", path);
	return fp;
}

static int
isnewruleset(char **toks, size_t ntoks)
{
	return ntoks > 2 && strcmp(toks[1], "for") == 0;
}

static struct Stringa
newcompls(char **toks, size_t ntoks)
{
	struct Stringa compls;

	compls.nstrs = ntoks;
	compls.strs = ecalloc(ntoks, sizeof(*compls.strs));
	while (ntoks-- > 0)
		compls.strs[ntoks] = estrdup(toks[ntoks]);
	return compls;
}

static struct Rule *
newrule(char **toks, size_t ntoks, int isnew, const char *config, size_t lineno)
{
	struct Rule *rule;
	regex_t reg;
	int res, type, n;
	char errbuf[BUFSIZE];

	if (strcmp(toks[1], "matches") == 0) {
		type = RULE_MATCHES;
	} else if (strcmp(toks[1], "types") == 0) {
		type = RULE_TYPES;
	} else if (strcmp(toks[1], "with") == 0) {
		type = RULE_WITH;
	} else {
		warnx("%s:%zu: unknown predicate \"%s\"", config, lineno, toks[1]);
		return NULL;
	}
	memset(&reg, 0, sizeof(reg));
	n = 2;
	if (type == RULE_MATCHES) {
		if (ntoks > 3) {
			if (strcmp(toks[3], "into") != 0) {
				warnx("%s:%zu: unknown argument \"%s\"", config, lineno, toks[3]);
				return NULL;
			}
			n = 4;
		} else {
			n = 3;
		}
		if ((res = regcomp(&reg, toks[2], REG_EXTENDED)) != 0) {
			if (regerror(res, &reg, errbuf, sizeof(errbuf)) > 0)
				warnx("%s:%zu: %s", config, lineno, errbuf);
			else
				warnx("%s:%zu: wrong regex \"%s\"", config, lineno, toks[2]);
			regfree(&reg);
			return NULL;
		}
	} else if (type == RULE_TYPES && ntoks != 3) {
		warnx("%s:%zu: syntax error", config, lineno);
		return NULL;
	} else if (type == RULE_WITH) {
		if (isnew) {
			warnx("%s:%zu: \"with\" predicates on global ruleset has no effect", config, lineno);
			return NULL;
		}
	}
	rule = emalloc(sizeof(*rule));
	*rule = (struct Rule){
		.type = type,
		.reg = reg,
		.compls = newcompls(toks + n, ntoks - n),
		.subj = estrdup(toks[0]),
	};
	return rule;
}

static int
isalnum_(char c)
{
	return (c >= 'A' && c <= 'Z') ||
	       (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') ||
	       c == '_';
}

static void
insertvalue(struct FrameQueue *frames, const char *name, const char *value, size_t len)
{
	struct Frame *frame;

	TAILQ_FOREACH(frame, frames, entries) {
		if (strcmp(frame->name, name) == 0) {
			free(frame->value);
			frame->value = estrndup(value, len);
			return;
		}
	}
	frame = emalloc(sizeof(*frame));
	*frame = (struct Frame){
		.name = estrdup(name),
		.value = (value != NULL && len > 0) ? estrndup(value, len) : NULL,
	};
	TAILQ_INSERT_HEAD(frames, frame, entries);
}

static const char *
lookupenv(struct FrameQueue *env, const char *name)
{
	struct Frame *frame;
	char *val;

	if (name == NULL)
		return "";
	TAILQ_FOREACH(frame, env, entries)
		if (strcmp(frame->name, name) == 0)
			return frame->value != NULL ? frame->value : "";
	val = getenv(name);
	return val != NULL ? val : "";
}

static void
readrules(struct RulesetQueue *sets, const char *config)
{
	enum {
		QUOTE,
		WORD,
	} state;
	struct FrameQueue env;
	struct Ruleset *set;
	struct Rule *rule;
	FILE *fp;
	size_t k, len, lineno;
	size_t linesize = 0;
	size_t tokindices[MAXTOKENS];
	ssize_t i, j, ntoks;
	ssize_t linelen;
	int setvar, newset;
	const char *envval;
	char *tokens[MAXTOKENS];
	char *line = NULL;
	char defconfig[PATH_MAX];
	char newvar[ENVVAR_MAX];
	char envvar[ENVVAR_MAX];

	if (config == NULL)
		config = getconfig(defconfig, sizeof(defconfig));
	fp = openrules(config);
	lineno = 0;
	TAILQ_INIT(sets);
	TAILQ_INIT(&env);
	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		lineno++;
		ntoks = 0;
		i = 0;
		while (isspace((unsigned char)line[i]))
			i++;
		while (linelen > 0 && isspace((unsigned char)line[linelen - 1]))
			line[--linelen] = '\0';
		if (strchr("#\n", line[i]) != NULL)
			continue;
		j = i;
		k = 0;
		setvar = 0;
		while (isalnum_(line[j]) && k < ENVVAR_MAX - 1)
			newvar[k++] = line[j++];
		if (j > i) {
			/* check environment-like variable assignment */
			while (isspace((unsigned char)line[j]))
				j++;
			if (line[j] == '=') {
				j++;
				while (isspace((unsigned char)line[j]))
					j++;
				newvar[k] = '\0';
				setvar = 1;
				i = j;
			}
		}
		state = WORD;
		for ( ; i < linelen && line[i] != '\0'; i++) {
			while (isspace((unsigned char)line[i]))
				i++;
			if (strchr("\n", line[i]) != NULL || ntoks == MAXTOKENS)
				continue;
			if (line[i] == '\'') {
				state = QUOTE;
				i++;
			} else {
				state = WORD;
			}
			j = i;
			tokindices[ntoks++] = i;
			while (j < linelen && line[i] != '\0') {
				if (state == WORD && isspace((unsigned char)line[i])) {
					line[j] = '\0';
					break;
				} else if (state == WORD && line[i] == '$') {
					k = 0;
					if (line[i+1] == '$') {
						line[j++] = '$';
						i += 2;
						continue;
					} else if (line[i+1] == '{') {
						i += 2;
						while (line[i] != '\0' && line[i] != '}' && k < ENVVAR_MAX - 1) {
							envvar[k++] = line[i++];
						}
						if (line[i] != '\0') {
							i++;
						}
					} else {
						i++;
						while (isalnum_(line[i]) && k < ENVVAR_MAX - 1) {
							envvar[k++] = line[i++];
						}
					}
					envvar[k] = '\0';
					if (k == 0)
						continue;
					envval = lookupenv(&env, envvar);
					len = strlen(envval);
					if (len + linelen + 1 > linesize) {
						line = erealloc(line, len + linelen + 1);
					}
					memmove(line + j + len, line + i, strlen(line + i) + 1);
					memcpy(line + j, envval, len);
					linelen -= i - j;
					linelen += len;
					j += len;
					i = j;
					line[linelen] = '\0';
					continue;
				} else if (state == QUOTE && line[i] == '\'') {
					if (isspace((unsigned char)line[i+1])) {
						line[j] = '\0';
						i++;
						break;
					} else if (line[i+1] == '\'') {
						line[j++] = '\'';
						i++;
					} else {
						state = WORD;
					}
				} else if (state == WORD && line[i] == '\'') {
					state = QUOTE;
				} else {
					line[j++] = line[i];
				}
				i++;
			}
			line[j] = '\0';
		}
		for (i = 0; i < ntoks; i++)
			tokens[i] = &line[tokindices[i]];
		if (setvar) {
			if (ntoks > 0)
				insertvalue(&env, estrdup(newvar), tokens[0], strlen(tokens[0]));
			else
				insertvalue(&env, estrdup(newvar), "", 0);
			continue;
		}
		if (ntoks < 3) {
			warnx("%s:%zu: syntax error", config, lineno);
			continue;
		}
		newset = isnewruleset(tokens, ntoks);
		if (TAILQ_EMPTY(sets) || newset) {
			set = emalloc(sizeof(*set));
			set->name.nstrs = 0;
			TAILQ_INIT(&set->rules);
			TAILQ_INSERT_TAIL(sets, set, entries);
		}
		if (newset) {
			if (strcmp(tokens[0], "rules") != 0) {
				warnx("%s:%zu: syntax error", config, lineno);
				continue;
			}
			set->name = newcompls(tokens + 2, ntoks - 2);
		} else {
			if ((rule = newrule(tokens, ntoks, newset, config, lineno)) == NULL)
				continue;
			TAILQ_INSERT_TAIL(&set->rules, rule, entries);
		}
	}
	fclose(fp);
}

static const char *
lookupvar(struct FrameQueue *globals, struct FrameQueue *locals, const char *data, const char *name)
{
	struct Frame *frame;

	if (name == NULL)
		return "";
	TAILQ_FOREACH(frame, locals, entries)
		if (strcmp(frame->name, name) == 0)
			return frame->value != NULL ? frame->value : "";
	TAILQ_FOREACH(frame, globals, entries)
		if (strcmp(frame->name, name) == 0)
			return frame->value != NULL ? frame->value : "";
	if (strcmp(name, "data") == 0)
		return data != NULL ? data : "";
	return "";
}

static int
matchruleset(struct Ruleset *set, magic_t magic, struct Arg *arg, char *actions, int local)
{
	struct Rule *rule;
	struct FrameQueue *frames;
	regmatch_t pmatch[MAXTOKENS];
	size_t i;
	regoff_t beg, len;
	int match;
	const char *val, *type;

	match = 1;
	frames = (local ? &arg->locals : &arg->globals);
	TAILQ_FOREACH(rule, &set->rules, entries) {
		switch (rule->type) {
		case RULE_MATCHES:
			val = lookupvar(&arg->globals, &arg->locals, arg->data, rule->subj);
			if (regexec(&rule->reg, val, MAXTOKENS, pmatch, 0) != 0) {
				match = 0;
				continue;
			}
			if (pmatch[0].rm_so != 0 || val[pmatch[0].rm_eo] != '\0') {
				match = 0;
				continue;
			}
			for (i = 0; i < rule->reg.re_nsub && i < rule->compls.nstrs; i++) {
				beg = pmatch[i + 1].rm_so;
				len = pmatch[i + 1].rm_eo - beg;
				if (beg >= 0 && len >= 0) {
					insertvalue(frames, rule->compls.strs[i], val + beg, len);
				} else {
					insertvalue(frames, rule->compls.strs[i], NULL, 0);
				}
			}
			break;
		case RULE_TYPES:
			val = lookupvar(&arg->globals, &arg->locals, arg->data, rule->subj);
			type = magic_file(magic, val);
			len = (type != NULL) ? strlen(type) : 0;
			insertvalue(frames, rule->compls.strs[0], type, len);
			break;
		case RULE_WITH:
			/* we deal with this later */
			break;
		}
	}
	if (!match)
		return 0;
	TAILQ_FOREACH(rule, &set->rules, entries) {
		switch (rule->type) {
		case RULE_WITH:
			if (strstr(actions, rule->subj) != NULL)
				return 1;
			break;
		default:
			break;
		}
	}
	return 0;
}

static void
runargs(struct Stringa cmd, struct Arg *args, size_t nargs, int dryrun)
{
	struct Stringa newargs;
	ssize_t beg, end;
	size_t i, j, len, size;
	const char *val;
	char *s, *name;
	char **argv;

	newargs.nstrs = nargs;
	s = cmd.strs[cmd.nstrs - 1];
	beg = end = -1;
	for (i = j = 0; s[i] != '\0'; i++) {
		if (s[i] == '%') {
			i++;
			if (s[i] == '%') {
				s[j++] = '%';
			} else if (s[i] == '{') {
				i++;
				beg = j;
				while (isalnum_(s[i]))
					s[j++] = s[i++];
				end = j;
				if (s[i] != '\0') {
					i++;
				}
			} else {
				beg = j;
				while (isalnum_(s[i]))
					s[j++] = s[i++];
				end = j;
			}
			continue;
		}
		s[j++] = s[i];
	}
	s[j] = '\0';
	len = strlen(cmd.strs[cmd.nstrs - 1]);
	name = NULL;
	if (beg >= 0 && end > beg) {
		len -= end - beg;
		name = estrndup(s + beg, end - beg);
	}
	newargs.strs = ecalloc(nargs, sizeof(*newargs.strs));
	for (i = 0; i < nargs; i++) {
		val = lookupvar(&args[i].globals, &args[i].locals, args[i].data, name);
		size = len + strlen(val) + 1;           /* +1 for '\0' */
		newargs.strs[i] = emalloc(size);
		snprintf(newargs.strs[i], size, "%.*s%s%s", (int)beg, s, val, s + end);
	}
	free(name);
	size = cmd.nstrs + nargs;
	argv = ecalloc(size, sizeof(*argv));
	for (i = 0; i < cmd.nstrs - 1; i++)
		argv[i] = cmd.strs[i];
	for (j = 0; j < nargs; j++)
		argv[i+j] = newargs.strs[j];
	argv[i+j] = NULL;
	if (dryrun) {
		for (i = 0; i < size - 1; i++)
			printf("%s%s", (i == 0 ? "" : " "), argv[i]);
		printf("\n");
	} else {
		if (efork() == 0) {
			if (efork() == 0) {
				execvp(argv[0], argv);
				err(1, "%s", argv[0]);
			}
			exit(0);
		}
		wait(NULL);
	}
	for (i = 0; i < nargs; i++)
		free(newargs.strs[i]);
	free(newargs.strs);
}

static void
openwith(struct Ruleset *set, struct Arg *args, int nargs, const char *actions, int dryrun)
{
	struct Rule *rule;
	size_t i;

	(void)args;
	(void)nargs;
	printf("plumbing ");
	for (i = 0; i < set->name.nstrs; i++)
		printf("%s%s", (i == 0 ? "" : " "), set->name.strs[i]);
	printf("\n");
	TAILQ_FOREACH(rule, &set->rules, entries) {
		if (rule->type == RULE_WITH && strstr(actions, rule->subj) != NULL) {
			runargs(rule->compls, args, nargs, dryrun);
			return;
		}
	}
}

static void
freerules(struct RulesetQueue *sets)
{
	struct Ruleset *set;
	struct Rule *rule;
	size_t i;

	while ((set = TAILQ_FIRST(sets)) != NULL) {
		TAILQ_REMOVE(sets, set, entries);
		while ((rule = TAILQ_FIRST(&set->rules)) != NULL) {
			TAILQ_REMOVE(&set->rules, rule, entries);
			for (i = 0; i < rule->compls.nstrs; i++)
				free(rule->compls.strs[i]);
			if (rule->type == RULE_MATCHES)
				regfree(&rule->reg);
			free(rule->subj);
			free(rule);
		}
		for (i = 0; i < set->name.nstrs; i++)
			free(set->name.strs[i]);
		free(set->name.strs);
		free(set);
	}
}

static void
freeargs(struct Arg *args, int nargs)
{
	struct Frame *frame;
	int i;

	for (i = 0; i < nargs; i++) {
		while ((frame = TAILQ_FIRST(&args[i].globals)) != NULL) {
			TAILQ_REMOVE(&args[i].globals, frame, entries);
			free(frame->name);
			free(frame->value);
		}
		while ((frame = TAILQ_FIRST(&args[i].locals)) != NULL) {
			TAILQ_REMOVE(&args[i].locals, frame, entries);
			free(frame->name);
			free(frame->value);
		}
	}
}

int
main(int argc, char *argv[])
{
	struct RulesetQueue sets;
	struct Ruleset *set, *foundset;
	struct Arg *args;
	magic_t magic;
	int i, c;
	int dryrun;
	char *cmd, *config, *actions;

	actions = ACTION_OPEN;
	dryrun = 0;
	config = NULL;
	if (argc > 0 && argv[0] != NULL) {
		if ((cmd = strchr(argv[0], '/')) != NULL)
			cmd++;
		else
			cmd = argv[0];
		if (strcmp(cmd, "open") == 0) {
			actions = ACTION_OPEN;
		} else if (strcmp(cmd, "edit") == 0) {
			actions = ACTION_EDIT;
		}
	}
	while ((c = getopt(argc, argv, "a:c:eon")) != -1) {
		switch (c) {
		case 'a':
			actions = optarg;
			break;
		case 'c':
			config = optarg;
			break;
		case 'e':
			actions = ACTION_EDIT;
			break;
		case 'n':
			dryrun = 1;
			break;
		case 'o':
			actions = ACTION_OPEN;
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc == 0)
		usage();
	args = ecalloc(argc, sizeof(*args));
	if ((magic = magic_open(MAGIC_SYMLINK | MAGIC_MIME_TYPE | MAGIC_PRESERVE_ATIME | MAGIC_ERROR)) == NULL)
		errx(1, "could not get magic cookie");
	if (magic_load(magic, NULL) == -1)
		errx(1, "could not load magic database");
	readrules(&sets, config);
	if (TAILQ_EMPTY(&sets)) {
		freerules(&sets);
		free(args);
		return 1;
	}
	foundset = NULL;
	for (i = 0; i < argc; i++) {
		args[i].data = argv[i];
		TAILQ_INIT(&args[i].globals);
		TAILQ_INIT(&args[i].locals);
		set = TAILQ_FIRST(&sets);
		(void)matchruleset(set, magic, &args[i], actions, 0);
		for (set = TAILQ_NEXT(set, entries);
		     i == 0 && set != NULL;
		     set = TAILQ_NEXT(set, entries)) {
			if (matchruleset(set, magic, &args[i], actions, 0)) {
				foundset = set;
				break;
			}
		}
		if (i > 0 && !matchruleset(foundset, magic, &args[i], actions, 1)) {
			foundset = NULL;
		}
		if (foundset == NULL) {
			break;
		}
	}
	magic_close(magic);
	if (foundset != NULL)
		openwith(foundset, args, argc, actions, dryrun);
	freerules(&sets);
	freeargs(args, argc);
	return (foundset == NULL);
}

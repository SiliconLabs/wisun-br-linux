#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>

#include "app_wsbrd/commandline.h"
#include "common/log.h"
#include "commandline.h"

enum {
    OPT_CAPTURE = 256,
    OPT_REPLAY,
};

struct option {
    const char *name;
    bool has_arg;
    void (*func)(const char *);
};

void __real_print_help_br(FILE *stream);
void __wrap_print_help_br(FILE *stream)
{
    __real_print_help_br(stream);
    fprintf(stream, "\n");
    fprintf(stream, "Extra options:\n");
    fprintf(stream, "  --capture=FILE        Record raw data received on UART and TUN interfaces, and save it to\n");
    fprintf(stream, "                          FILE. Also write additional timer information for replay.\n");
    fprintf(stream, "  --replay=FILE         Replay a sequence captured using --capture\n");
}

static void parse_opt_capture(const char *arg)
{
    BUG("Not yet implemented");
}

static void parse_opt_replay(const char *arg)
{
    BUG("Not yet implemented");
}

#define parsing_error(fmt, ...) do {                                     \
    fprintf(stderr, "%s: " fmt, program_invocation_name, ##__VA_ARGS__); \
    print_help_br(stderr);                                               \
    exit(1);                                                             \
} while (0)

static int fuzz_parse_opt(char **argv, const struct option *opt)
{
    size_t optlen = strlen(opt->name);

    if (strncmp(argv[0], opt->name, optlen))
        return 0;

    if (strlen(argv[0]) == optlen) { // '--foo bar' form
        if (!opt->has_arg) {
            opt->func(NULL);
            return 1;
        }
        if (!argv[1])
            parsing_error("option '%s' requires an argument\n", opt->name);
        opt->func(argv[1]);
        return 2;
    } else { // '--foo=bar' form
        if (argv[0][optlen] != '=')
            return 0;
        if (!opt->has_arg)
            parsing_error("option '%s' doesn't allow an argument\n", opt->name);
        opt->func(argv[0] + optlen + 1);
        return 1;
    }
}

/*
 * Parses one or two argument(s) depending if an option requires an parameter.
 * Returns the number of args correctly parsed (0, 1 or 2).
 */
static int fuzz_parse_arg(char **argv)
{
    static const struct option opts[] = {
        { "--capture", true, parse_opt_capture },
        { "--replay",  true, parse_opt_replay },
        { 0,           0,    0 },
    };
    int ret;

    for (const struct option *opt = opts; opt->name; opt++) {
        ret = fuzz_parse_opt(argv, opt);
        if (ret)
            return ret;
    }
    return 0;
}

/*
 * Parses commandline options for wsbrd-fuzz, and modifies argv
 * in place to only keep remaining arguments.
 * Returns the new length of argv.
 */
int fuzz_parse_commandline(char **argv)
{
    int i = 1, j = 1;
    int ret;

    while (argv[i]) {
        ret = fuzz_parse_arg(argv + i);
        if (ret)
            i += ret;
        else
            argv[j++] = argv[i++];
    }
    argv[j] = NULL;

    return j;
}

/*
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "app_wsbrd/commandline.h"
#include "app_wsbrd/wsbr.h"
#include "common/log.h"
#include "common/utils.h"
#include "wsbrd_fuzz.h"
#include "commandline.h"

enum {
    OPT_CAPTURE = 256,
    OPT_REPLAY,
};

struct option {
    const char *name;
    bool has_arg;
    void (*func)(struct fuzz_ctxt *, const char *);
};

void __real_print_help_br(FILE *stream);
void __wrap_print_help_br(FILE *stream)
{
    __real_print_help_br(stream);
    fprintf(stream, "\n");
    fprintf(stream, "Extra options:\n");
    fprintf(stream, "  --capture=FILE        Record raw data received on UART and TUN interfaces, and save it to\n");
    fprintf(stream, "                          FILE. Also write additional timer information for replay.\n");
    fprintf(stream, "  --capture-init=FILE   Record the RCP initialization phase to a separate file than --capture.\n");
    fprintf(stream, "  --replay=FILE         Replay a sequence captured using --capture. When specified more than\n");
    fprintf(stream, "                          once, files are replayed back to back from left to right.\n");
    fprintf(stream, "  --fuzz                Disable CRC check, stub security RNG, relax SPINEL checks, disable NVM.\n");
}

static void parse_opt_capture(struct fuzz_ctxt *ctxt, const char *arg)
{
    FATAL_ON(ctxt->capture_fd >= 0, 1, "--capture used more than once");
    FATAL_ON(ctxt->replay_count, 1, "using --capture and --replay at the same time");
    ctxt->capture_fd = open(arg, O_WRONLY | O_CREAT | O_TRUNC,
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    FATAL_ON(ctxt->capture_fd < 0, 2, "open '%s': %m", arg);
}

static void parse_opt_capture_init(struct fuzz_ctxt *ctxt, const char *arg)
{
    FATAL_ON(ctxt->capture_init_fd >= 0, 1, "--capture-init used more than once");
    ctxt->capture_init_fd = open(arg, O_WRONLY | O_CREAT | O_TRUNC,
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    FATAL_ON(ctxt->capture_init_fd < 0, 2, "open '%s': %m", arg);
}

static void parse_opt_replay(struct fuzz_ctxt *ctxt, const char *arg)
{
    int ret;

    FATAL_ON(ctxt->replay_count > ARRAY_SIZE(ctxt->replay_fds), 1,
        "--replay used too many times (max %zu)", ARRAY_SIZE(ctxt->replay_fds));
    FATAL_ON(ctxt->capture_fd >= 0, 1, "using --capture and --replay at the same time");
    ret = open(arg, O_RDONLY);
    FATAL_ON(ret < 0, 2, "open '%s': %m", arg);
    ctxt->replay_fds[ctxt->replay_count++] = ret;
    g_ctxt.config.uart_dev[0] = true; // UART device does not need to be specified
}

static void parse_opt_fuzz(struct fuzz_ctxt *ctxt, const char *arg)
{
    ctxt->fuzzing_enabled = true;
}

#define parsing_error(fmt, ...) do {                                     \
    fprintf(stderr, "%s: " fmt, program_invocation_name, ##__VA_ARGS__); \
    print_help_br(stderr);                                               \
    exit(1);                                                             \
} while (0)

static int fuzz_parse_opt(struct fuzz_ctxt *ctxt, char **argv, const struct option *opt)
{
    size_t optlen = strlen(opt->name);

    if (strncmp(argv[0], opt->name, optlen))
        return 0;

    if (strlen(argv[0]) == optlen) { // '--foo bar' form
        if (!opt->has_arg) {
            opt->func(ctxt, NULL);
            return 1;
        }
        if (!argv[1])
            parsing_error("option '%s' requires an argument\n", opt->name);
        opt->func(ctxt, argv[1]);
        return 2;
    } else { // '--foo=bar' form
        if (argv[0][optlen] != '=')
            return 0;
        if (!opt->has_arg)
            parsing_error("option '%s' doesn't allow an argument\n", opt->name);
        opt->func(ctxt, argv[0] + optlen + 1);
        return 1;
    }
}

/*
 * Parses one or two argument(s) depending if an option requires an parameter.
 * Returns the number of args correctly parsed (0, 1 or 2).
 */
static int fuzz_parse_arg(struct fuzz_ctxt *ctxt, char **argv)
{
    static const struct option opts[] = {
        { "--capture",      true,  parse_opt_capture },
        { "--capture-init", true,  parse_opt_capture_init },
        { "--replay",       true,  parse_opt_replay },
        { "--fuzz",         false, parse_opt_fuzz },
        { 0,                0,     0 },
    };
    int ret;

    for (const struct option *opt = opts; opt->name; opt++) {
        ret = fuzz_parse_opt(ctxt, argv, opt);
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
int fuzz_parse_commandline(struct fuzz_ctxt *ctxt, char **argv)
{
    int i = 1, j = 1;
    int ret;

    while (argv[i]) {
        ret = fuzz_parse_arg(ctxt, argv + i);
        if (ret)
            i += ret;
        else
            argv[j++] = argv[i++];
    }
    argv[j] = NULL;

    if (ctxt->capture_fd >= 0 || ctxt->replay_count)
        ctxt->rand_predictable = true;

    if (ctxt->capture_init_fd >= 0 && ctxt->capture_fd < 0)
        FATAL(1, "--capture-init used without --capture");

    return j;
}

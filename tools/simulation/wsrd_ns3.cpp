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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#include <string>
#include <vector>

#include <ns3/abort.h>
#include <ns3/sl-wisun-linux.hpp>

extern "C" {
#include "app_wsrd/app/wsrd.h"
#include "common/memutils.h"
#include "common/log.h"
#include "common/version.h"
}

#if SL_NS3_WISUN_LINUX_VERSION < VERSION(2, 2, 0) || SL_NS3_WISUN_LINUX_VERSION >= VERSION(3, 0, 0)
#error "Incompatible ns-3 version"
#endif

int g_simulation_id;
std::string g_capture_filename;
std::string g_capture_init_filename; // Unused

static void wsrd_ns3_cleanup(void *arg)
{
    char *config_filename = (char *)arg;
    int ret;

    ret = unlink(config_filename);
    WARN_ON(ret, "unlink %s: %m", config_filename);
}

void wsrd_ns3_main(const char *config)
{
    char config_filename[] = "/tmp/wsbrd-ns3-XXXXXX.conf";
    std::vector<char *> args;
    int config_fd;
    ssize_t size;

    BUG_ON(g_uart_cb.IsNull());
    BUG_ON(g_uart_fd < 0);

    config_fd = mkstemps(config_filename, strlen(".conf"));
    FATAL_ON(config_fd < 0, 1, "mkstemps: %m");
    size = write(config_fd, config, strlen(config));
    FATAL_ON(size < 0, 1, "write %s: %m", config_filename);
    if ((size_t)size < strlen(config))
        FATAL(1, "write %s: Short write", config_filename);
    close(config_fd);

    // Cast to non-const, wsbrd is trusted to not modify its arguments
    args.push_back((char *)"wsrd");
    args.push_back((char *)"-F");
    args.push_back(config_filename);
    args.push_back((char *)"-u/dev/null"); // Provide a UART devive so parse_commandline succeeds
    args.push_back(NULL);

    pthread_cleanup_push(wsrd_ns3_cleanup, config_filename);
    wsrd_main(args.size() - 1, (char **)args.data()); // Does not return
    pthread_cleanup_pop(true);
}

static char last_error[256];
extern "C" void __wrap___tr_printf(const char *color, const char *fmt, ...)
{
    va_list ap;

    // Hack: ERROR, FATAL and BUG pass "31" (red) or "91" (light red) as output
    // color
    if (!strcmp(color, "91") || !strcmp(color, "31")) {
        va_start(ap, fmt);
        vsnprintf(last_error, sizeof(last_error), fmt, ap);
        va_end(ap);
    }
    va_start(ap, fmt);
    __tr_vprintf(color, fmt, ap);
    va_end(ap);
}

extern "C" sighandler_t __wrap_signal(int signum, sighandler_t handler)
{
    errno = ENOSYS;
    return SIG_ERR;
}

// exit() is not thread-safe, so aborting is preferred.
extern "C" void __wrap_exit(int status)
{
    if (strlen(last_error))
        fprintf(stderr, "\x1b[31mwsrd: %s\x1b[0m\n", last_error);
    ns3::FatalImpl::FlushStreams();
    std::terminate();
}

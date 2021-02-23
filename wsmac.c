/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/select.h>

#include "wsmac.h"
#include "slist.h"
#include "log.h"
#include "bus_uart.h"
#include "hal_fhss_timer.h"
#include "os_timer.h"
#include "os_types.h"
#include "hal_interrupt.h"
#include "eventOS_scheduler.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP  "main"

// See warning in wsmac.h
struct wsmac_ctxt g_ctxt = { };
// See warning in os_types.h
struct os_ctxt g_os_ctxt = { };

void print_help(FILE *stream, int exit_code) {
    fprintf(stream, "Start Wi-SUN MAC emulation\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wisun-mac [OPTIONS] UART_DEVICE\n");
    fprintf(stream, "\n");
    fprintf(stream, "Examples:\n");
    fprintf(stream, "  wisun-mac /dev/pts/15\n");
    exit(exit_code);
}

void configure(struct wsmac_ctxt *ctxt, int argc, char *argv[])
{
    static const struct option opt_list[] = {
        { "help", no_argument, 0, 'h' },
        { 0,      0,           0,  0  }
    };
    int opt;

    while ((opt = getopt_long(argc, argv, "h", opt_list, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_help(stdout, 0);
                break;
            case '?':
            default:
                print_help(stderr, 1);
                break;
        }
    }
    if (argc != optind + 1)
        print_help(stderr, 1);
    ctxt->os_ctxt->data_fd = wsbr_uart_open(argv[optind + 0], 115200, false);
    ctxt->os_ctxt->trig_fd = ctxt->os_ctxt->data_fd;
}

void rx(struct wsmac_ctxt *ctxt)
{
    uint8_t buf[256];
    int len;

    len = wsbr_uart_tx(ctxt->os_ctxt, buf, sizeof(buf));
    (void)len;
    // FIXME: parse it and forward it to upper layers
}

int main(int argc, char *argv[])
{
    struct wsmac_ctxt *ctxt = &g_ctxt;
    struct fhss_timer_entry *fhss_timer;
    struct callback_timer *timer;
    struct timespec ts = { };
    int maxfd, ret;
    uint64_t val;
    fd_set rfds;

    ctxt->os_ctxt = &g_os_ctxt;
    pipe(ctxt->os_ctxt->event_fd);
    platform_critical_init();
    mbed_trace_init();
    configure(ctxt, argc, argv);

    for (;;) {
        maxfd = 0;
        FD_ZERO(&rfds);
        FD_SET(ctxt->os_ctxt->trig_fd, &rfds);
        maxfd = max(maxfd, ctxt->os_ctxt->trig_fd);
        FD_SET(ctxt->os_ctxt->event_fd[0], &rfds);
        maxfd = max(maxfd, ctxt->os_ctxt->event_fd[0]);
        SLIST_FOR_EACH_ENTRY(ctxt->os_ctxt->timers, timer, node) {
            FD_SET(timer->fd, &rfds);
            maxfd = max(maxfd, timer->fd);
        }
        SLIST_FOR_EACH_ENTRY(ctxt->os_ctxt->fhss_timers, fhss_timer, node) {
            FD_SET(fhss_timer->fd, &rfds);
            maxfd = max(maxfd, fhss_timer->fd);
        }
        if (ctxt->os_ctxt->uart_next_frame_ready)
            ret = pselect(maxfd + 1, &rfds, NULL, NULL, &ts, NULL);
        else
            ret = pselect(maxfd + 1, &rfds, NULL, NULL, NULL, NULL);
        if (ret < 0)
            FATAL(2, "pselect: %m");
        if (FD_ISSET(ctxt->os_ctxt->trig_fd, &rfds) || ctxt->os_ctxt->uart_next_frame_ready)
            rx(ctxt);
        if (FD_ISSET(ctxt->os_ctxt->event_fd[0], &rfds)) {
            read(ctxt->os_ctxt->event_fd[0], &val, sizeof(val));
            WARN_ON(val != 'W');
            eventOS_scheduler_run_until_idle();
        }
        SLIST_FOR_EACH_ENTRY(ctxt->os_ctxt->timers, timer, node) {
            if (FD_ISSET(timer->fd, &rfds)) {
                read(timer->fd, &val, sizeof(val));
                WARN_ON(val != 1);
                timer->fn(timer->fd, 0);
            }
        }
        SLIST_FOR_EACH_ENTRY(ctxt->os_ctxt->fhss_timers, fhss_timer, node) {
            if (FD_ISSET(fhss_timer->fd, &rfds)) {
                read(fhss_timer->fd, &val, sizeof(val));
                WARN_ON(val != 1);
                fhss_timer->fn(fhss_timer->arg, 0);
            }
        }
    }

    return 0;
}


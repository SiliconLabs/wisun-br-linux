/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <sys/select.h>

#include "mbed-trace/mbed_trace.h"
#include "nanostack-event-loop/eventOS_scheduler.h"
#include "nanostack/ns_virtual_rf_api.h"
#include "nanostack/sw_mac.h"
#include "nanostack/source/MAC/rf_driver_storage.h"

#include "wsmac.h"
#include "wsmac_mac.h"
#include "slist.h"
#include "log.h"
#include "bus_uart.h"
#include "hal_fhss_timer.h"
#include "hal_interrupt.h"
#include "os_timer.h"
#include "os_types.h"

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

int8_t virtual_rf_tx(const virtual_data_req_t *data_req, int8_t driver_id)
{
    struct wsmac_ctxt *ctxt = &g_ctxt;

    BUG_ON(driver_id != ctxt->rcp_driver_id);
    TRACE("RF tx msdu:");
    pr_hex(data_req->msdu, data_req->msduLength);
    TRACE("... parms:");
    pr_hex(data_req->parameters, data_req->parameter_length);
    ctxt->rf_driver->phy_driver->phy_tx_done_cb(ctxt->rcp_driver_id, 1, PHY_LINK_CCA_PREPARE, 1, 1);
    return 1;
}

void kill_handler(int signal)
{
    exit(3);
}

static mac_description_storage_size_t storage_sizes = {
    .device_decription_table_size = 32,
    .key_description_table_size = 4,
    .key_lookup_size = 1,
    .key_usage_size = 3,
};
static uint8_t rcp_mac[8] = { 10, 11, 12, 13, 14, 15, 16, 17 };

int main(int argc, char *argv[])
{
    struct wsmac_ctxt *ctxt = &g_ctxt;
    struct fhss_timer_entry *fhss_timer;
    struct callback_timer *timer;
    struct timespec ts = { };
    int maxfd, ret;
    uint64_t val;
    fd_set rfds;

    signal(SIGINT, kill_handler);
    ctxt->os_ctxt = &g_os_ctxt;
    pipe(ctxt->os_ctxt->event_fd);
    platform_critical_init();
    mbed_trace_init();
    eventOS_scheduler_init();
    configure(ctxt, argc, argv);
    ctxt->rcp_driver_id = virtual_rf_device_register(PHY_LINK_15_4_SUBGHZ_TYPE, 2043);
    if (ctxt->rcp_driver_id < 0)
        tr_err("%s: arm_net_phy_register: %d", __func__, ctxt->rcp_driver_id);
    ctxt->rf_driver = arm_net_phy_driver_pointer(ctxt->rcp_driver_id);
    BUG_ON(!ctxt->rf_driver);
    ctxt->rf_driver->phy_driver->arm_net_virtual_tx_cb = &virtual_rf_tx;
    arm_net_phy_mac64_set(rcp_mac, ctxt->rcp_driver_id);
    ctxt->rcp_mac_api = ns_sw_mac_create(ctxt->rcp_driver_id, &storage_sizes);
    if (!ctxt->rcp_mac_api)
        tr_err("%s: ns_sw_mac_create", __func__);

    // Initialize SW MAC
    ret = ctxt->rcp_mac_api->mac_initialize(ctxt->rcp_mac_api,
                                            wsmac_mcps_data_confirm,
                                            wsmac_mcps_data_indication,
                                            wsmac_mcps_purge_confirm,
                                            wsmac_mlme_confirm,
                                            wsmac_mlme_indication,
                                            0); // Parent ID?

    ret = ctxt->rcp_mac_api->mac_mcps_extension_enable(ctxt->rcp_mac_api,
                                                       wsmac_mcps_data_indication_ext,
                                                       wsmac_mcps_data_confirm_ext,
                                                       wsmac_mcps_ack_data_req_ext);

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
            uart_rx(ctxt);
        if (FD_ISSET(ctxt->os_ctxt->event_fd[0], &rfds)) {
            read(ctxt->os_ctxt->event_fd[0], &val, sizeof(val));
            WARN_ON(val != 'W');
            // You may use eventOS_scheduler_run_until_idle() instead of
            // eventOS_scheduler_dispatch_event() identify tasks that shcedule
            // themselves.
            // eventOS_scheduler_run_until_idle();
            eventOS_scheduler_dispatch_event();
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


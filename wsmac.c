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
#include <fcntl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pcap/pcap.h>

#include "mbed-trace/mbed_trace.h"
#include "nanostack-event-loop/eventOS_scheduler.h"
#include "nanostack/sw_mac.h"
#include "nanostack/source/MAC/rf_driver_storage.h"

#include "wsmac.h"
#include "wsmac_mac.h"
#include "wsmac_rf_driver.h"
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
    fprintf(stream, "  wisun-mac [OPTIONS] UART_DEVICE_NET UART_DEVICE_RF\n");
    fprintf(stream, "\n");
    fprintf(stream, "Options:\n");
    fprintf(stream, "  -m, --eui64=ADDR Set MAC address (EUI64) to ADDR (default: random)\n");
    fprintf(stream, "  -c, --pcap=FILE  Dump RF data to FILE\n");
    fprintf(stream, "  -w, --wireshark  Invoke wireshark and dump RF data into\n");
    fprintf(stream, "\n");
    fprintf(stream, "Examples:\n");
    fprintf(stream, "  wisun-mac /dev/pts/7 /dev/pts/15\n");
    exit(exit_code);
}

void configure_pcap_output(struct wsmac_ctxt *ctxt, const char *filename)
{
    ctxt->pcap_ctxt = pcap_open_dead(DLT_IEEE802_15_4_NOFCS, 0xFFFF);
    pcap_set_immediate_mode(ctxt->pcap_ctxt, 1);
    ctxt->pcap_dumper = pcap_dump_open(ctxt->pcap_ctxt, filename);
    FATAL_ON(!ctxt->pcap_dumper, 1, "%s: %s", optarg, pcap_geterr(ctxt->pcap_ctxt));
}

static void invoke_wireshark(struct wsmac_ctxt *ctxt)
{
    int ret;
    char file[] = "/tmp/wireshark-ws-XXXXXX";

    mktemp(file);
    mkfifo(file, 0600);
    ret = fork();
    FATAL_ON(ret < 0, 2);
    if (!ret) {
        execlp("wireshark", "wireshark", "-k", "-i", file, NULL);
        printf("wireshark invocation fail\n");
        exit(2);
    } else {
        configure_pcap_output(ctxt, file);
    }
}

void configure_mac(struct wsmac_ctxt *ctxt, const char *str)
{
    uint8_t *val = ctxt->eui64;
    int ret;

    ret = sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%*c",
                 &val[0], &val[1], &val[2], &val[3],
                 &val[4], &val[5], &val[6], &val[7]);
    FATAL_ON(ret != 8, 1, "malformated EUI64");
}

void fill_random(void *dest, size_t len)
{
    int rnd = open("/dev/urandom", O_RDONLY);

    read(rnd, dest, len);
    close(rnd);
}

void configure(struct wsmac_ctxt *ctxt, int argc, char *argv[])
{
    static const struct option opt_list[] = {
        { "eui64",     required_argument, 0, 'm' },
        { "pcap",      required_argument, 0, 'c' },
        { "wireshark", no_argument,       0, 'w' },
        { "help",      no_argument,       0, 'h' },
        { 0,           0,                 0,  0  }
    };
    int opt;

    fill_random(ctxt->eui64, sizeof(ctxt->eui64));
    ctxt->eui64[0] &= ~1;
    ctxt->eui64[0] |= 2;
    while ((opt = getopt_long(argc, argv, "hm:c:w", opt_list, NULL)) != -1) {
        switch (opt) {
            case 'w':
                invoke_wireshark(ctxt);
                break;
            case 'c':
                configure_pcap_output(ctxt, optarg);
                break;
            case 'm':
                configure_mac(ctxt, optarg);
                break;
            case 'h':
                print_help(stdout, 0);
                break;
            case '?':
            default:
                print_help(stderr, 1);
                break;
        }
    }
    if (argc != optind + 2)
        print_help(stderr, 1);
    ctxt->os_ctxt->data_fd = wsbr_uart_open(argv[optind + 0], 115200, false);
    ctxt->os_ctxt->trig_fd = ctxt->os_ctxt->data_fd;
    ctxt->rf_fd = wsbr_uart_open(argv[optind + 1], 115200, false);
}

void kill_handler(int signal)
{
    exit(3);
}

extern uint16_t channel;
void rf_rx(struct wsmac_ctxt *ctxt)
{
    uint8_t buf[MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE];
    uint8_t hdr[6];
    uint16_t pkt_len;
    int len;
    struct pcap_pkthdr pcap_hdr;

    len = read(ctxt->rf_fd, hdr, 6);
    if (len != 6 || hdr[0] != 'x' || hdr[1] != 'x') {
        TRACE("RF rx msdu: DROP invalid data");
        return;
    }
    pkt_len = ((uint16_t *)hdr)[1];
    len = read(ctxt->rf_fd, buf, pkt_len);
    WARN_ON(len != pkt_len);
    TRACE("RF rx msdu on channel %d (while listening on %d)", ((uint16_t *)hdr)[2], channel);
    if (ctxt->pcap_dumper) {
        gettimeofday(&pcap_hdr.ts, NULL);
        pcap_hdr.caplen = len;
        pcap_hdr.len = len;
        pcap_dump((uint8_t *)ctxt->pcap_dumper, &pcap_hdr, buf);
    }

    ctxt->rf_driver->phy_driver->phy_rx_cb(buf, len, 200, 0, ctxt->rcp_driver_id);
}

static mac_description_storage_size_t storage_sizes = {
    .device_decription_table_size = 32,
    .key_description_table_size = 4,
    .key_lookup_size = 1,
    .key_usage_size = 3,
};

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
    arm_net_phy_mac64_set(ctxt->eui64, ctxt->rcp_driver_id);
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

    wsmac_reset_ind(ctxt);
    for (;;) {
        maxfd = 0;
        FD_ZERO(&rfds);
        FD_SET(ctxt->rf_fd, &rfds);
        maxfd = max(maxfd, ctxt->rf_fd);
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
        if (ctxt->os_ctxt->uart_next_frame_ready || ctxt->rf_frame_cca_progress)
            ret = pselect(maxfd + 1, &rfds, NULL, NULL, &ts, NULL);
        else
            ret = pselect(maxfd + 1, &rfds, NULL, NULL, NULL, NULL);
        if (ret < 0)
            FATAL(2, "pselect: %m");
        if (FD_ISSET(ctxt->rf_fd, &rfds))
            rf_rx(ctxt);
        if (ctxt->rf_frame_cca_progress) {
            ctxt->rf_frame_cca_progress = false;
            ctxt->rf_driver->phy_driver->phy_tx_done_cb(ctxt->rcp_driver_id, 1, PHY_LINK_CCA_PREPARE, 1, 1);
            ctxt->rf_driver->phy_driver->phy_tx_done_cb(ctxt->rcp_driver_id, 1, PHY_LINK_TX_SUCCESS, 1, 1);
        }
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


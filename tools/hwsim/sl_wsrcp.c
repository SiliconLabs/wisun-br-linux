/*
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <pty.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#ifdef HAVE_LIBPCAP
#  include <pcap/pcap.h>
#endif
#include "common/bus_uart.h"
#include "common/events_scheduler.h"
#include "common/os_types.h"
#include "common/slist.h"
#include "common/log.h"
#include "common/log_legacy.h"
#include "stack/mac/sw_mac.h"

#include "hal_fhss_timer.h"
#include "sl_wsrcp_mac.h"
#include "sl_rf_driver.h"
#include "os_timer.h"
#include "version.h"

#include "sl_wsrcp.h"

#define TRACE_GROUP  "main"

// See warning in wsmac.h
struct wsmac_ctxt g_ctxt = { };
// See warning in common/os_types.h
struct os_ctxt g_os_ctxt = { };
// FIXME: should be const
mac_description_storage_size_t g_storage_sizes = {
    .device_description_table_size = ARRAY_SIZE(g_ctxt.neighbor_timings),
    .key_description_table_size = 4,
    .key_lookup_size = 1,
    .key_usage_size = 3,
};

void print_help(FILE *stream, int exit_code) {
    fprintf(stream, "\n");
    fprintf(stream, "Start Wi-SUN MAC emulation\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wisun-mac [OPTIONS] UART_DEVICE_NET SOCKET_RF\n");
    fprintf(stream, "\n");
    fprintf(stream, "Options:\n");
    fprintf(stream, "  -m, --eui64=ADDR      Set MAC address (EUI64) to ADDR (default: random)\n");
    fprintf(stream, "  -T, --trace=TAG[,TAG] Enable traces marked with TAG. Valid tags: rf, chan,\n");
    fprintf(stream, "                        bus, hdlc, hif, hif-extra\n");
    fprintf(stream, "  -c, --pcap=FILE       Dump RF data to FILE\n");
    fprintf(stream, "  -w, --wireshark       Invoke wireshark and dump RF data into\n");
    fprintf(stream, "\n");
    fprintf(stream, "Examples:\n");
    fprintf(stream, "  wisun-mac /dev/pts/7 /tmp/rf_server\n");
    exit(exit_code);
}

void configure_pcap_output(struct wsmac_ctxt *ctxt, const char *filename)
{
#ifdef HAVE_LIBPCAP
    ctxt->pcap_ctxt = pcap_open_dead(DLT_IEEE802_15_4_NOFCS, 0xFFFF);
    pcap_set_immediate_mode(ctxt->pcap_ctxt, 1);
    ctxt->pcap_dumper = pcap_dump_open(ctxt->pcap_ctxt, filename);
    FATAL_ON(!ctxt->pcap_dumper, 1, "%s: %s", optarg, pcap_geterr(ctxt->pcap_ctxt));
#else
    FATAL(1, "Support for libpcap not compiled");
#endif
}

static void invoke_wireshark(struct wsmac_ctxt *ctxt)
{
    int ret;
    char file[] = "/tmp/wireshark-ws-XXXXXX\0fifo";

    mkdtemp(file);
    file[strlen(file)] = '/';
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

int socket_open(const char *path)
{
    struct sockaddr_un addr = {
        .sun_family = AF_UNIX
    };
    int fd;
    int ret;

    strcpy(addr.sun_path, path);
    fd = socket(AF_UNIX, SOCK_SEQPACKET, 0); // use SOCK_SEQPACKET or SOCK_STREAM
    FATAL_ON(fd < 0, 2, "socket %s: %m", path);
    ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    FATAL_ON(ret < 0, 2, "connect %s: %m", path);
    return fd;
}

int pty_open(const char *dest_path, int bitrate, bool hardflow)
{
    static const struct {
        int val;
        int symbolic;
    } conversion[] = {
        { 9600, B9600 },
        { 19200, B19200 },
        { 38400, B38400 },
        { 57600, B57600 },
        { 115200, B115200 },
        { 230400, B230400 },
        { 460800, B460800 },
        { 921600, B921600 },
    };
    char pty_path[255];
    struct termios tty = { };
    int sym_bitrate = -1;
    int master, slave;
    int i, ret;

    for (i = 0; i < ARRAY_SIZE(conversion); i++)
        if (conversion[i].val == bitrate)
            sym_bitrate = conversion[i].symbolic;
    if (sym_bitrate < 0)
        FATAL(1, "invalid bitrate: %d", bitrate);
    cfsetispeed(&tty, sym_bitrate);
    cfsetospeed(&tty, sym_bitrate);
    cfmakeraw(&tty);
    tty.c_cc[VTIME] = 0;
    tty.c_cc[VMIN] = 1;
    tty.c_iflag &= ~IXON;
    tty.c_iflag &= ~IXOFF;
    tty.c_iflag &= ~IXANY;
    tty.c_cflag &= ~HUPCL;
    tty.c_cflag |= CLOCAL;
    if (hardflow)
        tty.c_cflag |= CRTSCTS;
    else
        tty.c_cflag &= ~CRTSCTS;
    ret = openpty(&master, &slave, pty_path, &tty, NULL);
    if (ret < 0)
        FATAL(1, "openpty: %m");
    ret = unlink(dest_path);
    if (ret < 0 && errno != ENOENT)
        FATAL(1, "unlink: %m");
    ret = symlink(pty_path, dest_path);
    if (ret < 0)
        FATAL(1, "symlink: %m");
    return master;
}

void configure(struct wsmac_ctxt *ctxt, int argc, char *argv[])
{
    static const struct {
        char *name;
        int val;
    } valid_traces[] = {
        { "rf",        TR_RF },
        { "chan",      TR_CHAN },
        { "bus",       TR_BUS },
        { "hdlc",      TR_HDLC },
        { "hif",       TR_HIF },
        { "hif-extra", TR_HIF_EXTRA },
    };
    static const struct option opt_list[] = {
        { "eui64",     required_argument, 0, 'm' },
        { "pcap",      required_argument, 0, 'c' },
        { "trace",     required_argument, 0, 'T' },
        { "wireshark", no_argument,       0, 'w' },
        { "help",      no_argument,       0, 'h' },
        { 0,           0,                 0,  0  }
    };
    char *tag;
    int opt, i;

    fill_random(ctxt->eui64, sizeof(ctxt->eui64));
    ctxt->eui64[0] &= ~1;
    ctxt->eui64[0] |= 2;
    while ((opt = getopt_long(argc, argv, "hm:c:T:w", opt_list, NULL)) != -1) {
        switch (opt) {
            case 'm':
                configure_mac(ctxt, optarg);
                break;
            case 'T':
                tag = strtok(optarg, ",");
                do {
                    for (i = 0; i < ARRAY_SIZE(valid_traces); i++) {
                        if (!strcmp(valid_traces[i].name, tag)) {
                            g_enabled_traces |= valid_traces[i].val;
                            break;
                        }
                    }
                    if (i == ARRAY_SIZE(valid_traces))
                        FATAL(1, "invalid tag: %s", tag);
                } while ((tag = strtok(NULL, ",")));
                break;
            case 'c':
                configure_pcap_output(ctxt, optarg);
                break;
            case 'w':
                invoke_wireshark(ctxt);
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
    ctxt->rf_fd = socket_open(argv[optind + 1]);
    ctxt->os_ctxt->data_fd = pty_open(argv[optind + 0], 115200, false);
    ctxt->os_ctxt->trig_fd = ctxt->os_ctxt->data_fd;
}

struct mac_api *init_mac_api(int rcp_driver_id)
{
    struct mac_api *rcp_mac_api;
    int ret;

    rcp_mac_api = ns_sw_mac_create(rcp_driver_id, &g_storage_sizes);
    BUG_ON(!rcp_mac_api);

    // Initialize SW MAC
    ret = rcp_mac_api->mac_initialize(rcp_mac_api,
                                            wsmac_mcps_data_confirm,
                                            wsmac_mcps_data_indication,
                                            wsmac_mcps_purge_confirm,
                                            wsmac_mlme_confirm,
                                            wsmac_mlme_indication,
                                            0); // Parent ID?
    WARN_ON(ret);

    ret = rcp_mac_api->mac_mcps_extension_enable(rcp_mac_api,
                                                       wsmac_mcps_data_indication_ext,
                                                       wsmac_mcps_data_confirm_ext,
                                                       wsmac_mcps_ack_data_req_ext);
    WARN_ON(ret);
    return rcp_mac_api;
}

void kill_handler(int signal)
{
    exit(3);
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

    INFO("Silicon Labs Wi-SUN RCP simulation %s", version_hwsim_str);
    signal(SIGINT, kill_handler);
    signal(SIGHUP, kill_handler);
    signal(SIGTERM, kill_handler);
    ctxt->os_ctxt = &g_os_ctxt;
    event_scheduler_init(&ctxt->scheduler);
    configure(ctxt, argc, argv);
    ctxt->rcp_driver_id = virtual_rf_device_register(PHY_LINK_15_4_SUBGHZ_TYPE, 2043);
    if (ctxt->rcp_driver_id < 0)
        tr_error("%s: arm_net_phy_register: %d", __func__, ctxt->rcp_driver_id);
    ctxt->rf_driver = arm_net_phy_driver_pointer(ctxt->rcp_driver_id);
    BUG_ON(!ctxt->rf_driver);
    arm_net_phy_mac64_set(ctxt->eui64, ctxt->rcp_driver_id);
    ctxt->rcp_mac_api = init_mac_api(ctxt->rcp_driver_id);

    wsmac_reset_ind(ctxt, true);
    for (;;) {
        maxfd = 0;
        FD_ZERO(&rfds);
        FD_SET(ctxt->rf_fd, &rfds);
        maxfd = MAX(maxfd, ctxt->rf_fd);
        FD_SET(ctxt->os_ctxt->trig_fd, &rfds);
        maxfd = MAX(maxfd, ctxt->os_ctxt->trig_fd);
        FD_SET(ctxt->scheduler.event_fd[0], &rfds);
        maxfd = MAX(maxfd, ctxt->scheduler.event_fd[0]);
        SLIST_FOR_EACH_ENTRY(ctxt->timers, timer, node) {
            FD_SET(timer->fd, &rfds);
            maxfd = MAX(maxfd, timer->fd);
        }
        SLIST_FOR_EACH_ENTRY(ctxt->fhss_timers, fhss_timer, node) {
            FD_SET(fhss_timer->fd, &rfds);
            maxfd = MAX(maxfd, fhss_timer->fd);
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
            wsmac_rx_host(ctxt);
        if (FD_ISSET(ctxt->scheduler.event_fd[0], &rfds)) {
            read(ctxt->scheduler.event_fd[0], &val, sizeof(val));
            WARN_ON(val != 'W');
            // You may use event_scheduler_run_until_idle() instead of
            // event_scheduler_dispatch_event() identify tasks that shcedule
            // themselves.
            // event_scheduler_run_until_idle();
            if (event_scheduler_dispatch_event())
                event_scheduler_signal();
        }
        SLIST_FOR_EACH_ENTRY(ctxt->timers, timer, node) {
            if (FD_ISSET(timer->fd, &rfds)) {
                ret = read(timer->fd, &val, sizeof(val));
                WARN_ON(ret < sizeof(val), "cancelled timer?");
                WARN_ON(val != 1, "missing timers: %u", (unsigned int)val - 1);
                timer->fn(timer->fd, 0);
            }
        }
        SLIST_FOR_EACH_ENTRY(ctxt->fhss_timers, fhss_timer, node) {
            if (FD_ISSET(fhss_timer->fd, &rfds)) {
                ret = read(fhss_timer->fd, &val, sizeof(val));
                WARN_ON(ret < sizeof(val), "cancelled fhss_timer?");
                WARN_ON(val != 1, "missing fhss_timer: %u", (unsigned int)val - 1);
                fhss_timer->fn(fhss_timer->arg, 0);
            }
        }
    }

    return 0;
}


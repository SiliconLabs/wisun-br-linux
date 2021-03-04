/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <sys/select.h>

#include "log.h"
#include "slist.h"
#include "wsbr.h"
#include "wsbr_mac.h"
#include "tun.h"
#include "bus_uart.h"
#include "bus_spi.h"
#include "os_types.h"
#include "os_timer.h"
#include "hal_interrupt.h"
#include "hal_fhss_timer.h"
#include "sw_mac.h"
#include "mac_api.h"
#include "ns_virtual_rf_api.h"
#include "ns_file_system.h"
#include "ws_bbr_api.h"
#include "eventOS_scheduler.h"
#include "eventOS_event.h"
#include "fhss_api.h"
#include "ws_management_api.h"
#include "mbed-trace/mbed_trace.h"
#include "nanostack/source/MAC/rf_driver_storage.h"
#define TRACE_GROUP  "main"

// See warning in wsbr.h
struct wsbr_ctxt g_ctxt = { };
// See warning in os_types.h
struct os_ctxt g_os_ctxt = { };

void print_help(FILE *stream, int exit_code) {
    fprintf(stream, "Start Wi-SUN border router\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wisun-br -u [OPTIONS] UART_DEVICE\n");
    fprintf(stream, "  wisun-br -s [OPTIONS] SPI_DEVICE GPIO_FILE\n");
    fprintf(stream, "  wisun-br -s [OPTIONS] SPI_DEVICE GPIO_NUMBER\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -u                    Use UART bus\n");
    fprintf(stream, "  -s                    Use SPI bus\n");
    fprintf(stream, "  -t TUN                Map a specific TUN device (eg. allocated with 'ip tuntap add tun0')\n");
    fprintf(stream, "  -n, --network=NAME    Set Wi-SUN network name (default \"Wi-SN\")\n");
    fprintf(stream, "  -d, --domain=COUNTRY  Set Wi-SUN regulatory domain. Valid values: WW, EU (default), NA,\n");
    fprintf(stream, "                          JP...\n");
    fprintf(stream, "  -m, --mode=VAL        Set operating mode. Valid values: 1a, 1b, 2a, 2b, 3 (default), 4a,\n");
    fprintf(stream, "                          4b and 5\n");
    fprintf(stream, "  -c, --class=VAL       Set operating class. Valid values: 1, 2 (default) or 3\n");
    fprintf(stream, "\n");
    fprintf(stream, "UART options\n");
    fprintf(stream, "  -b, --baudrate=BAUDRATE  UART baudrate: 9600, 19200, 38400, 57600, 115200 (default),\n");
    fprintf(stream, "                           230400, 460800, 921600\n");
    fprintf(stream, "  -H, --hardflow           Hardware CTS/RTS flow control (default: disabled)\n");
    fprintf(stream, "\n");
    fprintf(stream, "SPI options:\n");
    fprintf(stream, "  -f, --frequency=FREQUENCY  Clock frequency (default: 1000000)\n");
    fprintf(stream, "\n");
    fprintf(stream, "Examples:\n");
    fprintf(stream, "  wisun-br -u /dev/ttyUSB0 -H\n");
    fprintf(stream, "  wisun-br -s /dev/spi1.1 141\n");
    fprintf(stream, "  wisun-br -s /dev/spi1.1 /sys/class/gpio/gpio141/value\n");
    exit(exit_code);
}

void configure(struct wsbr_ctxt *ctxt, int argc, char *argv[])
{
    static const int valid_ws_modes[] = { 0x1a, 0x1b, 0x2a, 0x2b, 0x03, 0x4a, 0x4b, 0x05 };
    static const struct {
        char *name;
        int val;
    } valid_ws_domains[] = {
        { "WW", REG_DOMAIN_WW }, // World wide
        { "NA", REG_DOMAIN_NA }, // North America
        { "JP", REG_DOMAIN_JP }, // Japan
        { "EU", REG_DOMAIN_EU }, // European Union
        { "CH", REG_DOMAIN_CH }, // China
        { "IN", REG_DOMAIN_IN }, // India
        { "MX", REG_DOMAIN_MX }, //
        { "BZ", REG_DOMAIN_BZ }, // Brazil
        { "AZ", REG_DOMAIN_AZ }, // Australia
        { "NZ", REG_DOMAIN_NZ }, // New zealand
        { "KR", REG_DOMAIN_KR }, // Korea
        { "PH", REG_DOMAIN_PH }, //
        { "MY", REG_DOMAIN_MY }, //
        { "HK", REG_DOMAIN_HK }, //
        { "SG", REG_DOMAIN_SG }, // band 866-869
        { "TH", REG_DOMAIN_TH }, //
        { "VN", REG_DOMAIN_VN }, //
        { "SG", REG_DOMAIN_SG_H }, // band 920-925
    };
    static const struct option opt_list[] = {
        { "help",        no_argument,       0,  'h' },
        { "tun",         required_argument, 0,  't' },
        { "network",     required_argument, 0,  'n' },
        { "domain",      required_argument, 0,  'd' },
        { "mode",        required_argument, 0,  'm' },
        { "class",       required_argument, 0,  'c' },
        { "baudrate",    required_argument, 0,  'b' },
        { "hardflow",    no_argument,       0,  'H' },
        { "frequency",   required_argument, 0,  'f' },
        { 0,             0,                 0,   0  }
    };
    char *end_ptr;
    char bus = 0;
    int baudrate = 115200;
    int frequency = 1000000;
    bool hardflow = false;
    int opt, i;

    ctxt->ws_class = 2;
    ctxt->ws_domain = REG_DOMAIN_EU;
    ctxt->ws_mode = 0x3;
    strcpy(ctxt->ws_name, "Wi-SUN");
    while ((opt = getopt_long(argc, argv, "usf:Hb:t:n:d:m:h", opt_list, NULL)) != -1) {
        switch (opt) {
            case 'u':
            case 's':
                if (bus)
                    print_help(stderr, 1);
                bus = opt;
                break;
            case 't':
                strncpy(ctxt->tun_dev, optarg, sizeof(ctxt->tun_dev) - 1);
                break;
            case 'n':
                strncpy(ctxt->ws_name, optarg, sizeof(ctxt->ws_name) - 1);
                break;
            case 'd':
                ctxt->ws_domain = -1;
                for (i = 0; i < ARRAY_SIZE(valid_ws_domains); i++) {
                    if (!strcmp(valid_ws_domains[i].name, optarg)) {
                        ctxt->ws_domain = valid_ws_domains[i].val;
                        break;
                    }
                }
                if (ctxt->ws_domain < 0)
                    FATAL(1, "invalid domain: %s", optarg);
                break;
            case 'm':
                ctxt->ws_mode = strtoul(optarg, &end_ptr, 16);
                if (*end_ptr)
                    FATAL(1, "invalid mode: %s", optarg);
                for (i = 0; i < ARRAY_SIZE(valid_ws_modes); i++)
                    if (valid_ws_modes[i] == ctxt->ws_mode)
                        break;
                if (i == ARRAY_SIZE(valid_ws_modes))
                    FATAL(1, "invalid mode: %s", optarg);
                break;
            case 'c':
                ctxt->ws_class = strtoul(optarg, &end_ptr, 10);
                if (*end_ptr || ctxt->ws_class > 3)
                    FATAL(1, "invalid operating class: %s", optarg);
                break;
            case 'b':
                baudrate = strtoul(optarg, &end_ptr, 10);
                if (*end_ptr)
                    FATAL(1, "invalid bitrate: %s", optarg);
                break;
            case 'f':
                frequency = strtoul(optarg, &end_ptr, 10);
                if (*end_ptr)
                    FATAL(1, "invalid frequency: %s", optarg);
                break;
            case 'H':
                hardflow = true;
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
    if (bus == 's') {
        if (argc != optind + 2)
            print_help(stderr, 1);
        ctxt->rcp_tx = wsbr_spi_tx;
        ctxt->rcp_rx = wsbr_spi_rx;
        ctxt->os_ctxt->data_fd = wsbr_spi_open(argv[optind + 0], frequency, 0);
        ctxt->os_ctxt->trig_fd = wsbr_gpio_open(argv[optind + 1], false);
        ctxt->os_ctxt->spi_recv_window = UINT16_MAX;
    } else if (bus == 'u') {
        if (argc != optind + 1)
            print_help(stderr, 1);
        ctxt->rcp_tx = wsbr_uart_tx;
        ctxt->rcp_rx = wsbr_uart_rx;
        ctxt->os_ctxt->data_fd = wsbr_uart_open(argv[optind + 0], baudrate, hardflow);
        ctxt->os_ctxt->trig_fd = ctxt->os_ctxt->data_fd;
    } else {
        print_help(stderr, 1);
    }
}

void rcp_rx(struct wsbr_ctxt *ctxt)
{
    uint8_t buf[256];
    int len;

    len = ctxt->rcp_rx(ctxt->os_ctxt, buf, sizeof(buf));
    printf("** Recv:\n");
    pr_hex(buf, len);
    // FIXME: parse it and forwward it to upper layers
}

int8_t rcp_tx(const virtual_data_req_t *data_req, int8_t driver_id)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(driver_id != ctxt->rcp_driver_id);
    printf("** Send:\n");
    pr_hex(data_req->parameters, data_req->parameter_length);
    pr_hex(data_req->msdu, data_req->msduLength);
    // FIXME: convert the data to spinel and call ctxt->rcp_tx(ctxt, ... )
    ctxt->tun_driver->phy_tx_done_cb(ctxt->rcp_driver_id, 1, PHY_LINK_TX_SUCCESS, 0, 0);
    return 0;
}

static void wsbr_configure_fhss(struct wsbr_ctxt *ctxt)
{
    int ret;

    ret = ws_management_node_init(ctxt->rcp_if_id, ctxt->ws_domain,
                                  ctxt->ws_name, &wsbr_fhss);
    WARN_ON(ret);
    ret = ws_management_regulatory_domain_set(ctxt->rcp_if_id, ctxt->ws_domain,
                                              ctxt->ws_class, ctxt->ws_mode);
    WARN_ON(ret);
    if (ctxt->ws_domain == 0xFE) {
        FATAL(2, "Not yet supported");
        // ret = ws_management_channel_plan_set(ctxt->rcp_if_id, ...);
        // WARN_ON(ret);
    }
    // FIXME: allow to customize that
    // ret = ws_management_fhss_unicast_channel_function_configure(ctxt->rcp_if_id, ...);
    // WARN_ON(ret);
    // ret = ws_management_fhss_broadcast_channel_function_configure(ctxt->rcp_if_id, ...);
    // WARN_ON(ret);
    // ret = ws_management_fhss_timing_configure(ctxt->rcp_if_id, ...);
    // WARN_ON(ret);
    // ret = ws_management_network_size_set(ctxt->rcp_if_id, NETWORK_SIZE_SMALL);
    // WARN_ON(ret);
    // ret = ws_management_timing_parameters_set(ctxt->rcp_if_id, ...);
    // WARN_ON(ret);
    // ret = ws_bbr_rpl_parameters_set(ctxt->rcp_if_id, ...);
    // WARN_ON(ret);
}

static void wsbr_tasklet(struct arm_event_s *event)
{
    static uint8_t tun_prefix[16] = { };
    struct wsbr_ctxt *ctxt = &g_ctxt;

    switch (event->event_type) {
        case ARM_LIB_TASKLET_INIT_EVENT:
            // The tasklet that call arm_nwk_interface_configure_*_bootstrap_set()
            // will be used to receive ARM_LIB_NWK_INTERFACE_EVENT.
            if (arm_nwk_interface_configure_6lowpan_bootstrap_set(ctxt->rcp_if_id,
                                                                  NET_6LOWPAN_BORDER_ROUTER,
                                                                  NET_6LOWPAN_WS))
                WARN("arm_nwk_interface_configure_6lowpan_bootstrap_set");
            if (arm_nwk_interface_configure_ipv6_bootstrap_set(ctxt->tun_if_id,
                                                               NET_IPV6_BOOTSTRAP_AUTONOMOUS,
                                                               tun_prefix))
                WARN("arm_nwk_interface_configure_ipv6_bootstrap_set");
            wsbr_configure_fhss(ctxt);
            if (arm_nwk_interface_up(ctxt->tun_if_id))
                 WARN("arm_nwk_interface_up TUN");
            if (arm_nwk_interface_up(ctxt->rcp_if_id))
                 WARN("arm_nwk_interface_up RCP");
            if (ws_bbr_start(ctxt->rcp_if_id, ctxt->tun_if_id))
                 WARN("ws_bbr_start");
            break;
        case ARM_LIB_NWK_INTERFACE_EVENT:
            if (event->event_id == ctxt->tun_if_id) {
                printf("get event for tun interface\n");
            } else if (event->event_id == ctxt->rcp_if_id) {
                printf("get event for ws interface\n");
            } else {
                WARN("received unknown network event: %d", event->event_id);
            }
            break;
        default:
            WARN("received unknown event: %d", event->event_type);
            break;
    }
}

static struct wsbr_mac wsbr_mac = {
    .mac_api.mac_initialize = wsbr_mac_init,
    .mac_api.mac_mcps_edfe_enable = wsbr_mac_edfe_ext_init,
    .mac_api.mac_mcps_extension_enable = wsbr_mac_mcps_ext_init,

    .mac_api.mac_storage_sizes_get = wsbr_mac_storage_sizes_get,
    .mac_api.mac64_set = wsbr_mac_addr_set,
    .mac_api.mac64_get = wsbr_mac_addr_get,

    .mac_api.mlme_req = wsbr_mlme,
    .mac_api.mcps_data_req = wsbr_mcps_req,
    .mac_api.mcps_data_req_ext = wsbr_mcps_req_ext,
    .mac_api.mcps_purge_req = wsbr_mcps_purge,

    .mac_api.phyMTU = MAC_IEEE_802_15_4_MAX_PHY_PACKET_SIZE,
};

void kill_handler(int signal)
{
    exit(3);
}

int main(int argc, char *argv[])
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct callback_timer *timer;
    struct fhss_timer_entry *fhss_timer;
    fd_set rfds, efds;
    int maxfd, ret;
    uint64_t val;
    struct timespec ts = { };

    signal(SIGINT, kill_handler);
    ctxt->os_ctxt = &g_os_ctxt;
    pipe(ctxt->os_ctxt->event_fd);
    platform_critical_init();
    mbed_trace_init();
    configure(ctxt, argc, argv);
    ns_file_system_set_root_path("/tmp/wsbr_");

    if (net_init_core())
        tr_err("%s: net_init_core", __func__);

    wsbr_tun_init(ctxt);

    ctxt->rcp_if_id = arm_nwk_interface_lowpan_init(&wsbr_mac.mac_api, "ws0");
    if (ctxt->rcp_if_id < 0)
        tr_err("%s: arm_nwk_interface_lowpan_init: %d", __func__, ctxt->rcp_if_id);

    if (eventOS_event_handler_create(&wsbr_tasklet, ARM_LIB_TASKLET_INIT_EVENT) < 0)
        tr_err("%s: eventOS_event_handler_create", __func__);

    for (;;) {
        maxfd = 0;
        FD_ZERO(&rfds);
        FD_ZERO(&efds);
        if (ctxt->os_ctxt->trig_fd == ctxt->os_ctxt->data_fd)
            FD_SET(ctxt->os_ctxt->trig_fd, &rfds); // UART
        else
            FD_SET(ctxt->os_ctxt->trig_fd, &efds); // SPI + GPIO
        maxfd = max(maxfd, ctxt->os_ctxt->trig_fd);
        FD_SET(ctxt->tun_fd, &rfds);
        maxfd = max(maxfd, ctxt->tun_fd);
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
        // FIXME: consider poll() usage
        if (ctxt->os_ctxt->uart_next_frame_ready)
            ret = pselect(maxfd + 1, &rfds, NULL, &efds, &ts, NULL);
        else
            ret = pselect(maxfd + 1, &rfds, NULL, &efds, NULL, NULL);
        if (ret < 0)
            FATAL(2, "pselect: %m");
        if (FD_ISSET(ctxt->tun_fd, &rfds))
            wsbr_tun_read(ctxt);
        if (FD_ISSET(ctxt->os_ctxt->event_fd[0], &rfds)) {
            read(ctxt->os_ctxt->event_fd[0], &val, sizeof(val));
            WARN_ON(val != 'W');
            eventOS_scheduler_run_until_idle();
        }
        if (FD_ISSET(ctxt->os_ctxt->trig_fd, &rfds) ||
            FD_ISSET(ctxt->os_ctxt->trig_fd, &efds) ||
            ctxt->os_ctxt->uart_next_frame_ready)
            rcp_rx(ctxt);
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


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
#include <sys/select.h>

#include "log.h"
#include "slist.h"
#include "wsbr.h"
#include "tun.h"
#include "bus_uart.h"
#include "bus_spi.h"
#include "os_timer.h"
#include "hal_interrupt.h"
#include "net_interface.h"
#include "sw_mac.h"
#include "mac_api.h"
#include "ethernet_mac_api.h"
#include "ns_virtual_rf_api.h"
#include "ws_bbr_api.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP  "main"

// See warning in wsbr.h
struct wsbr_ctxt g_ctxt = { };

void print_help(FILE *stream, int exit_code) {
    fprintf(stream, "Start Wi_SUN border router\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wisun-br -u [OPTIONS] UART_DEVICE\n");
    fprintf(stream, "  wisun-br -s [OPTIONS] SPI_DEVICE GPIO_FILE\n");
    fprintf(stream, "  wisun-br -s [OPTIONS] SPI_DEVICE GPIO_NUMBER\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -u      Use UART bus\n");
    fprintf(stream, "  -s      Use SPI bus\n");
    fprintf(stream, "  -t TUN  Map a specific TUN device (eg. allocated with 'ip tuntap add tun0')\n");
    fprintf(stream, "\n");
    fprintf(stream, "UART options\n");
    fprintf(stream, "  -b, --baudrate=BAUDRATE  UART baudrate: 9600,19200,38400,57600,115200 (default),230400,460800,921600\n");
    fprintf(stream, "  -H, --hardflow           Hardware CTS/RTS flow control (default disabled)\n");
    fprintf(stream, "\n");
    fprintf(stream, "SPI options:\n");
    fprintf(stream, "  -f, --frequency=FREQUENCY  Clock frequency (default 1000000)\n");
    fprintf(stream, "\n");
    fprintf(stream, "Exemples:\n");
    fprintf(stream, "  wisun-br -u /dev/ttyUSB0 -H\n");
    fprintf(stream, "  wisun-br -s /dev/spi1.1 141\n");
    fprintf(stream, "  wisun-br -s /dev/spi1.1 /sys/class/gpio/gpio141/value\n");
    exit(exit_code);
}

void configure(struct wsbr_ctxt *ctxt, int argc, char *argv[])
{
    static const struct option opt_list[] = {
        { "help",        no_argument,       0,  'h' },
        { "tun",         required_argument, 0,  't' },
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
    int opt;

    while ((opt = getopt_long(argc, argv, "usf:Hb:t:h", opt_list, NULL)) != -1) {
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
        ctxt->rcp_fd = wsbr_spi_open(argv[optind + 0], frequency, 0);
        ctxt->rcp_trig_fd = wsbr_gpio_open(argv[optind + 1], false);
    } else if (bus == 'u') {
        if (argc != optind + 1)
            print_help(stderr, 1);
        ctxt->rcp_fd = wsbr_uart_open(argv[optind + 0], baudrate, hardflow);
        ctxt->rcp_trig_fd = ctxt->rcp_fd;
    } else {
        print_help(stderr, 1);
    }
    ctxt->tun_fd = wsbr_tun_open(ctxt->tun_dev);
}

static mac_description_storage_size_t storage_sizes = {
    .device_decription_table_size = 32, // FIXME: we have plenty of memory. Increase this value
    .key_description_table_size = 4,
    .key_lookup_size = 1,
    .key_usage_size = 3,
};

static uint8_t rcp_mac[8] = { 10, 11, 12, 13, 14, 15, 16, 17 };
static uint8_t tun_mac[8] = { 20, 21, 22, 23, 24, 25, 26, 27 };

static int8_t tun_tx(uint8_t *buf, uint16_t len, uint8_t tx_handle, data_protocol_e protocol)
{
    tr_info("%s: FIXME\n", __func__);
    return 0;
}

static struct phy_device_driver_s tun_driver = {
    /* link_type must match with ifr.ifr_flags:
     *   IFF_TAP | IFF_NO_PI -> PHY_LINK_ETHERNET_TYPE
     *   IFF_TUN | IFF_NO_PI -> PHY_LINK_SLIP
     *   IFF_TUN -> PHY_LINK_TUN
     */
    .link_type = PHY_LINK_TUN,
    .PHY_MAC = tun_mac,
    .data_request_layer = IPV6_DATAGRAMS_DATA_FLOW,
    .driver_description = (char *)"TUN BH",
    .tx = tun_tx,
};

int main(int argc, char *argv[])
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct callback_timer *timer;
    fd_set rfds;
    int maxfd, ret;
    uint64_t timer_val;

    platform_critical_init();
    mbed_trace_init();
    configure(ctxt, argc, argv);

    if (net_init_core())
        tr_err("%s: net_init_core", __func__);

    ctxt->rcp_driver_id = virtual_rf_device_register(PHY_LINK_15_4_SUBGHZ_TYPE, 2043);
    if (ctxt->rcp_driver_id < 0)
        tr_err("%s: arm_net_phy_register: %d", __func__, ctxt->rcp_driver_id);
    arm_net_phy_mac64_set(rcp_mac, ctxt->rcp_driver_id);
    ctxt->rcp_mac_api = ns_sw_mac_create(ctxt->rcp_driver_id, &storage_sizes);
    if (!ctxt->rcp_mac_api)
        tr_err("%s: ns_sw_mac_create", __func__);
    ctxt->rcp_if_id = arm_nwk_interface_lowpan_init(ctxt->rcp_mac_api, "ws0");
    if (ctxt->rcp_if_id < 0)
        tr_err("%s: arm_nwk_interface_lowpan_init: %d", __func__, ctxt->rcp_if_id);

    ctxt->tun_driver = &tun_driver;
    ctxt->tun_driver_id = arm_net_phy_register(ctxt->tun_driver);
    if (ctxt->tun_driver_id < 0)
        tr_err("%s: arm_net_phy_register: %d", __func__, ctxt->tun_driver_id);
    ctxt->tun_mac_api = ethernet_mac_create(ctxt->tun_driver_id);
    if (!ctxt->tun_mac_api)
        tr_err("%s: ethernet_mac_create", __func__);
    ctxt->tun_if_id = arm_nwk_interface_ethernet_init(ctxt->tun_mac_api, "bh0");
    if (ctxt->tun_if_id < 0)
        tr_err("%s: arm_nwk_interface_ethernet_init: %d", __func__, ctxt->tun_if_id);

    if (ws_bbr_start(ctxt->rcp_if_id, ctxt->tun_if_id))
        tr_err("%s: ws_bbr_start", __func__);

    for (;;) {
        maxfd = 0;
        FD_ZERO(&rfds);
        FD_SET(ctxt->tun_fd, &rfds);
        maxfd = max(maxfd, ctxt->tun_fd);
        SLIST_FOR_EACH_ENTRY(ctxt->timers, timer, node) {
            FD_SET(timer->fd, &rfds);
            maxfd = max(maxfd, timer->fd);
        }
        ret = pselect(maxfd + 1, &rfds, NULL, NULL, NULL, NULL);
        if (ret < 0)
            FATAL(2, "pselect: %m");
        if (FD_ISSET(ctxt->tun_fd, &rfds))
            wsbr_tun_read(ctxt);
        SLIST_FOR_EACH_ENTRY(ctxt->timers, timer, node) {
            if (FD_ISSET(timer->fd, &rfds)) {
                read(timer->fd, &timer_val, sizeof(timer_val));
                timer->fn(timer->fd, 0);
            }
        }
    }

    return 0;
}


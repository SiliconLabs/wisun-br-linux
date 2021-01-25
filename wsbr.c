/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "log.h"
#include "wsbr.h"
#include "bus_uart.h"
#include "bus_spi.h"
#include "hal_interrupt.h"
#include "net_interface.h"
#include "sw_mac.h"
#include "mac_api.h"
#include "ethernet_mac_api.h"
#include "ns_virtual_rf_api.h"
#include "ws_bbr_api.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP  "main"

void print_help(FILE *stream, int exit_code) {
    fprintf(stream, "Start Wi_SUN border router\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wisun-br -u [OPTIONS] UART_DEVICE\n");
    fprintf(stream, "  wisun-br -s [OPTIONS] SPI_DEVICE GPIO_FILE\n");
    fprintf(stream, "  wisun-br -s [OPTIONS] SPI_DEVICE GPIO_NUMBER\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -u                     Use UART bus\n");
    fprintf(stream, "  -s                     Use SPI bus\n");
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

    while ((opt = getopt_long(argc, argv, "usf:Hb:h", opt_list, NULL)) != -1) {
        switch (opt) {
            case 'u':
            case 's':
                if (bus)
                    print_help(stderr, 1);
                bus = opt;
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
        ctxt->fd_bus = wsbr_spi_open(argv[optind + 0], frequency, 0);
        ctxt->fd_trig = wsbr_gpio_open(argv[optind + 1], false);
    } else if (bus == 'u') {
        if (argc != optind + 1)
            print_help(stderr, 1);
        ctxt->fd_bus = wsbr_uart_open(argv[optind + 0], baudrate, hardflow);
        ctxt->fd_trig = ctxt->fd_bus;
    } else {
        print_help(stderr, 1);
    }
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

static struct phy_device_driver_s tun_phy_driver = {
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
    struct wsbr_ctxt ctxt;
    mac_api_t *rcp_mac_api;
    eth_mac_api_t *tun_mac_api;
    int rcp_driver_id, rcp_if_id;
    int tun_driver_id, tun_if_id;

    platform_critical_init();
    mbed_trace_init();
    configure(&ctxt, argc, argv);

    if (net_init_core())
        tr_err("%s: net_init_core", __func__);

    rcp_driver_id = virtual_rf_device_register(PHY_LINK_15_4_SUBGHZ_TYPE, 2043);
    if (rcp_driver_id < 0)
        tr_err("%s: arm_net_phy_register: %d", __func__, rcp_driver_id);
    arm_net_phy_mac64_set(rcp_mac, rcp_driver_id);
    rcp_mac_api = ns_sw_mac_create(rcp_driver_id, &storage_sizes);
    if (!rcp_mac_api)
        tr_err("%s: ns_sw_mac_create", __func__);
    rcp_if_id = arm_nwk_interface_lowpan_init(rcp_mac_api, "ws0");
    if (rcp_if_id < 0)
        tr_err("%s: arm_nwk_interface_lowpan_init: %d", __func__, rcp_if_id);

    tun_driver_id = arm_net_phy_register(&tun_phy_driver);
    if (tun_driver_id < 0)
        tr_err("%s: arm_net_phy_register: %d", __func__, tun_driver_id);
    tun_mac_api = ethernet_mac_create(tun_driver_id);
    if (!tun_mac_api)
        tr_err("%s: ethernet_mac_create", __func__);
    tun_if_id = arm_nwk_interface_ethernet_init(tun_mac_api, "bh0");
    if (tun_if_id < 0)
        tr_err("%s: arm_nwk_interface_ethernet_init: %d", __func__, tun_if_id);

    if (ws_bbr_start(rcp_if_id, tun_if_id))
        tr_err("%s: ws_bbr_start", __func__);

    return 0;
}


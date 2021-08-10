/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/select.h>

#include "mbed-trace/mbed_trace.h"
#include "nanostack-event-loop/eventOS_event.h"
#include "nanostack-event-loop/eventOS_scheduler.h"
#include "nanostack/fhss_api.h"
#include "nanostack/mac_api.h"
#include "nanostack/ns_file_system.h"
#include "nanostack/sw_mac.h"
#include "nanostack/ws_bbr_api.h"
#include "nanostack/ws_management_api.h"
#include "nanostack/source/6LoWPAN/ws/ws_common_defines.h"
#include "nanostack/source/MAC/rf_driver_storage.h"

#include "host-common/log.h"
#include "host-common/slist.h"
#include "wsbr.h"
#include "wsbr_mac.h"
#include "tun.h"
#include "host-common/bus_uart.h"
#include "host-common/bus_spi.h"
#include "host-common/os_types.h"
#include "host-common/os_timer.h"
#include "host-common/hal_interrupt.h"

// See warning in wsbr.h
struct wsbr_ctxt g_ctxt = {
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

    // FIXME: retrieve from RCP. Normally, MAC layer set this value when it
    // receive the mac802_15_4Mode request.
    // .mac_api.phyMTU = MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE,
    .mac_api.phyMTU = 2043,
};

// See warning in host-common/os_types.h
struct os_ctxt g_os_ctxt = { };

void print_help(FILE *stream, int exit_code) {
    fprintf(stream, "Start Wi-SUN border router\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wsbrd -u [OPTIONS] UART_DEVICE\n");
    fprintf(stream, "  wsbrd -s [OPTIONS] SPI_DEVICE GPIO_FILE\n");
    fprintf(stream, "  wsbrd -s [OPTIONS] SPI_DEVICE GPIO_NUMBER\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -u                    Use UART bus\n");
    fprintf(stream, "  -s                    Use SPI bus\n");
    fprintf(stream, "  -t TUN                Map a specific TUN device (eg. allocated with 'ip tuntap add tun0')\n");
    fprintf(stream, "\n");
    fprintf(stream, "Wi-SUN related options:\n");
    fprintf(stream, "  -n, --network=NAME    Set Wi-SUN network name (default \"Wi-SN\")\n");
    fprintf(stream, "  -d, --domain=COUNTRY  Set Wi-SUN regulatory domain. Valid values: WW, EU (default), NA,\n");
    fprintf(stream, "                          JP...\n");
    fprintf(stream, "  -m, --mode=VAL        Set operating mode. Valid values: 1a, 1b, 2a, 2b, 3 (default), 4a,\n");
    fprintf(stream, "                          4b and 5\n");
    fprintf(stream, "  -c, --class=VAL       Set operating class. Valid values: 1, 2 (default) or 3\n");
    fprintf(stream, "\n");
    fprintf(stream, "Wi-SUN network authentication:\n");
    fprintf(stream, "  The following option are mandatory. Every option has to specify a file in PEM\n");
    fprintf(stream, "  or DER format.\n");
    fprintf(stream, "  -K, --key=FILE        Private key (keep it secret)\n");
    fprintf(stream, "  -C, --cert=FILE       Certificate for the key\n");
    fprintf(stream, "  -A, --authority=FILE  Certificate of the authority (CA) (shared with all devices\n");
    fprintf(stream, "                        of the network)\n");
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
    fprintf(stream, "  wsbrd -u /dev/ttyUSB0 -H -C cert.pem -A ca.pem -K key.pem\n");
    fprintf(stream, "  wsbrd -s -n my_network -C cert.pem -A ca.pem -K key.pem /dev/spi1.1 141\n");
    fprintf(stream, "  wsbrd -s /dev/spi1.1 /sys/class/gpio/gpio141/value -C cert.pem -A ca.pem -K key.pem\n");
    exit(exit_code);
}

size_t read_cert(const char *filename, const uint8_t **ptr)
{
    uint8_t *tmp;
    int fd, ret;
    struct stat st;

    fd = open(filename, O_RDONLY);
    FATAL_ON(fd < 0, 1, "%s: %d %m", filename, fd);
    ret = fstat(fd, &st);
    FATAL_ON(ret < 0, 1, "fstat: %s: %m", filename);

    /* See https://github.com/ARMmbed/mbedtls/issues/3896 and
     * mbedtls_x509_crt_parse()
     */
    tmp = malloc(st.st_size + 1);
    tmp[st.st_size] = 0;
    ret = read(fd, tmp, st.st_size);
    FATAL_ON(ret != st.st_size, 1, "read: %s: %m", filename);
    close(fd);
    *ptr = tmp;

    if (strstr(tmp, "-----BEGIN CERTIFICATE-----"))
        return st.st_size + 1;
    else
        return st.st_size;
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
        { "tun",         required_argument, 0,  't' },
        { "network",     required_argument, 0,  'n' },
        { "domain",      required_argument, 0,  'd' },
        { "mode",        required_argument, 0,  'm' },
        { "class",       required_argument, 0,  'c' },
        { "key",         required_argument, 0,  'K' },
        { "cert",        required_argument, 0,  'C' },
        { "certificate", required_argument, 0,  'C' },
        { "authority",   required_argument, 0,  'A' },
        { "baudrate",    required_argument, 0,  'b' },
        { "frequency",   required_argument, 0,  'f' },
        { "hardflow",    no_argument,       0,  'H' },
        { "help",        no_argument,       0,  'h' },
        { 0,             0,                 0,   0  }
    };
    char *end_ptr;
    char bus = 0;
    int baudrate = 115200;
    int frequency = 1000000;
    bool hardflow = false;
    int opt, i;

    ctxt->ws_class = 1;
    ctxt->ws_domain = REG_DOMAIN_EU;
    ctxt->ws_mode = 0x1a;
    strcpy(ctxt->ws_name, "Wi-SUN");
    while ((opt = getopt_long(argc, argv, "ust:n:d:m:c:K:C:A:b:f:Hh", opt_list, NULL)) != -1) {
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
            case 'K':
                if (ctxt->tls_own.key)
                    FATAL(1, "--key can be specified only one time");
                ctxt->tls_own.key_len = read_cert(optarg, &ctxt->tls_own.key);
                break;
            case 'C':
                if (ctxt->tls_own.cert)
                    FATAL(1, "--cert can be specified only one time");
                ctxt->tls_own.cert_len = read_cert(optarg, &ctxt->tls_own.cert);
                break;
            case 'A':
                if (ctxt->tls_ca.cert)
                    FATAL(1, "--authority can be specified only one time");
                ctxt->tls_ca.cert_len = read_cert(optarg, &ctxt->tls_ca.cert);
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
    if (!ctxt->tls_own.key)
        FATAL(1, "You must specify --key");
    if (!ctxt->tls_own.cert)
        FATAL(1, "You must specify --cert");
    if (!ctxt->tls_ca.cert)
        FATAL(1, "You must specify --authority");
    if (bus == 's') {
        if (argc != optind + 2)
            print_help(stderr, 1);
        ctxt->rcp_tx = spi_tx;
        ctxt->rcp_rx = spi_rx;
        ctxt->os_ctxt->data_fd = spi_open(argv[optind + 0], frequency, 0);
        ctxt->os_ctxt->trig_fd = gpio_open(argv[optind + 1], false);
        ctxt->os_ctxt->spi_recv_window = UINT16_MAX;
    } else if (bus == 'u') {
        if (argc != optind + 1)
            print_help(stderr, 1);
        ctxt->rcp_tx = uart_tx;
        ctxt->rcp_rx = uart_rx;
        ctxt->os_ctxt->data_fd = uart_open(argv[optind + 0], baudrate, hardflow);
        ctxt->os_ctxt->trig_fd = ctxt->os_ctxt->data_fd;
    } else {
        print_help(stderr, 1);
    }
}

static void wsbr_configure_ws(struct wsbr_ctxt *ctxt)
{
    int ret;

    ret = ws_management_node_init(ctxt->rcp_if_id, ctxt->ws_domain,
                                  ctxt->ws_name, (struct fhss_timer *)-1);
    WARN_ON(ret);

    WARN_ON(ctxt->ws_domain == 0xFE, "Not supported");
    ret = ws_management_regulatory_domain_set(ctxt->rcp_if_id, ctxt->ws_domain,
                                              ctxt->ws_class, ctxt->ws_mode);
    WARN_ON(ret);

    // FIXME: allow to customize the values below using command line

    // Default value as specified in ws_cfg_fhss_default_set().
    // You may also use CHANNEL_FUNCTION_FIXED and a true value instead of
    // 0xFFFF
    // Note that calling ws_management_fhss_timing_configure() is redundant
    // with the two function calls bellow.
    ret = ws_management_fhss_unicast_channel_function_configure(ctxt->rcp_if_id, WS_DH1CF, 0xFFFF,
                                                                WS_FHSS_UC_DWELL_INTERVAL);
    WARN_ON(ret);
    ret = ws_management_fhss_broadcast_channel_function_configure(ctxt->rcp_if_id, WS_DH1CF, 0xFFFF,
                                                                  WS_FHSS_BC_DWELL_INTERVAL, WS_FHSS_BC_INTERVAL);
    WARN_ON(ret);

    // You may also use NETWORK_SIZE_SMALL
    // Note that calls to ws_management_timing_parameters_set() and
    // ws_bbr_rpl_parameters_set() are done by the function below.
    ret = ws_management_network_size_set(ctxt->rcp_if_id, NETWORK_SIZE_AUTOMATIC);
    WARN_ON(ret);

    ret = ws_device_min_sens_set(ctxt->rcp_if_id, 174 - 93);
    WARN_ON(ret);

    // ret = ws_test_gtk_set(ctxt->rcp_if_id, gtks);
    // WARN_ON(ret);

    ret = arm_network_own_certificate_add(&ctxt->tls_own);
    WARN_ON(ret);

    ret = arm_network_trusted_certificate_add(&ctxt->tls_ca);
    WARN_ON(ret);
}

static void wsbr_tasklet(struct arm_event_s *event)
{
    const char *const nwk_events[] = {
        "ARM_NWK_BOOTSTRAP_READY",
        "ARM_NWK_RPL_INSTANCE_FLOODING_READY",
        "ARM_NWK_SET_DOWN_COMPLETE",
        "ARM_NWK_NWK_SCAN_FAIL",
        "ARM_NWK_IP_ADDRESS_ALLOCATION_FAIL",
        "ARM_NWK_DUPLICATE_ADDRESS_DETECTED",
        "ARM_NWK_AUHTENTICATION_START_FAIL",
        "ARM_NWK_AUHTENTICATION_FAIL",
        "ARM_NWK_NWK_CONNECTION_DOWN",
        "ARM_NWK_NWK_PARENT_POLL_FAIL",
        "ARM_NWK_PHY_CONNECTION_DOWN"
    };
    // FIXME: Random prefix
    static uint8_t tun_prefix[16] = {
        0xfd, 0x01, 0x12, 0x36, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
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
            wsbr_configure_ws(ctxt);
            if (arm_nwk_interface_up(ctxt->tun_if_id))
                 WARN("arm_nwk_interface_up TUN");
            if (arm_nwk_interface_up(ctxt->rcp_if_id))
                 WARN("arm_nwk_interface_up RCP");
            if (ws_bbr_start(ctxt->rcp_if_id, ctxt->tun_if_id))
                 WARN("ws_bbr_start");
            break;
        case ARM_LIB_NWK_INTERFACE_EVENT:
            if (event->event_id == ctxt->tun_if_id) {
                TRACE("get event for tun interface: %s", nwk_events[event->event_data]);
            } else if (event->event_id == ctxt->rcp_if_id) {
                TRACE("get event for ws interface: %s", nwk_events[event->event_data]);
            } else {
                WARN("received unknown network event: %d", event->event_id);
            }
            break;
        default:
            WARN("received unknown event: %d", event->event_type);
            break;
    }
}

void kill_handler(int signal)
{
    exit(3);
}

int main(int argc, char *argv[])
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct callback_timer *timer;
    fd_set rfds, efds;
    int maxfd, ret;
    uint64_t val;
    struct timespec ts = { };

    signal(SIGINT, kill_handler);
    ctxt->os_ctxt = &g_os_ctxt;
    pipe(ctxt->os_ctxt->event_fd);
    platform_critical_init();
    mbed_trace_init();
    mbed_trace_config_set(TRACE_ACTIVE_LEVEL_ALL | TRACE_MODE_COLOR);
    eventOS_scheduler_init();
    configure(ctxt, argc, argv);
    wsbr_tun_init(ctxt);
    ns_file_system_set_root_path("/tmp/wsbr_");

    wsbr_rcp_reset(ctxt);
    while (!ctxt->reset_done)
        rcp_rx(ctxt);

    wsbr_rcp_get_hw_addr(ctxt);
    while (!ctxt->hw_addr_done)
        rcp_rx(ctxt);
     memcpy(ctxt->dynamic_mac, ctxt->hw_mac, sizeof(ctxt->dynamic_mac));

    if (net_init_core())
        BUG("net_init_core");

    ctxt->rcp_if_id = arm_nwk_interface_lowpan_init(&ctxt->mac_api, "ws0");
    if (ctxt->rcp_if_id < 0)
        BUG("arm_nwk_interface_lowpan_init: %d", ctxt->rcp_if_id);

    if (eventOS_event_handler_create(&wsbr_tasklet, ARM_LIB_TASKLET_INIT_EVENT) < 0)
        BUG("eventOS_event_handler_create");

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
    }

    return 0;
}


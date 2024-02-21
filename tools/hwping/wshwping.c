/*
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <poll.h>
#include <unistd.h>
#include <getopt.h>
#include <termios.h>
#include "common/log.h"
#include "common/bits.h"
#include "common/bus_uart.h"
#include "common/bus.h"
#include "common/hif.h"
#include "common/spinel.h"
#include "common/bus_cpc.h"
#include "common/named_values.h"
#include "common/iobuf.h"
#include "common/memutils.h"
#include "common/version.h"

enum {
  MODE_TX = 1,
  MODE_RX = 2,
};

static const struct name_value accepted_modes[] = {
    { "tx",   MODE_TX },
    { "rx",   MODE_RX },
    { "dual", MODE_TX | MODE_RX },
    { NULL,  -1 },
};

const struct name_value valid_traces[] = {
    { "bus",       TR_BUS },
    { "cpc",       TR_CPC },
    { "hdlc",      TR_HDLC },
    { "hif",       TR_HIF },
    { "hif-extra", TR_HIF_EXTRA },
    { NULL },
};

struct commandline_args {
    uint8_t mode;
    char cpc_instance[256];
    char uart_device[256];
    int uart_baudrate;
    int payload_size;
    int number_of_exchanges;
    int window;
    bool reset;
    bool quiet;
    bool verbose;
};

void print_help(FILE *stream, int exit_code)
{
    fprintf(stream, "\n");
    fprintf(stream, "Stress the hardware link between the Linux host and the Wi-SUN RCP device\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wshwping [OPTIONS] MODE\n");
    fprintf(stream, "\n");
    fprintf(stream, "MODE can be RX, TX or DUAL\n");
    fprintf(stream, "\n");
    fprintf(stream, "Options:\n");
    fprintf(stream, "  -u, --uart=UART_DEVICE Use UART bus (default: /dev/ttyACM0)\n");
    fprintf(stream, "  -C, --cpc=CPC_INSTANCE Use CPC instance (ie. cpcd_0)\n");
    fprintf(stream, "  -B, --baurate=VAL      Configure UART with this baudrate (default: 115200)\n");
    fprintf(stream, "  -s, --size=SIZE        Size of the payload in frames (default: 512)\n");
    fprintf(stream, "  -c, --count=NUM        Number of frames to send/receive (default: 100)\n");
    fprintf(stream, "  -w, --window=NUM       Send NUM requests ahead of the replies. These frames\n");
    fprintf(stream, "                         are not accounted in results (default: auto)\n");
    fprintf(stream, "  -r, --reset            Reset the RCP before measurement\n");
    fprintf(stream, "  -q, --quiet            Do not show progress\n");
    fprintf(stream, "  -v, --verbose          Show intermediate results\n");
    fprintf(stream, "  -T, --trace=TAG[,TAG]  Enable traces marked with TAG. Valid tags: bus, cpc, hdlc, hif,\n");
    fprintf(stream, "                         and hif-extra\n");
    fprintf(stream, "\n");
    exit(exit_code);
}

void parse_commandline(struct commandline_args *cmd, int argc, char *argv[])
{
    const char *opts_short = "u:C:B:s:c:w:rT:qvhl";
    static const struct option opts_long[] = {
        { "uart",     required_argument, 0,  'u' },
        { "cpc",      required_argument, 0,  'C' },
        { "baudrate", required_argument, 0,  'B' },
        { "size",     required_argument, 0,  's' },
        { "count",    required_argument, 0,  'c' },
        { "window",   required_argument, 0,  'w' },
        { "trace",    required_argument, 0,  'T' },
        { "reset",    no_argument,       0,  'r' },
        { "quiet",    no_argument,       0,  'q' },
        { "verbose",  no_argument,       0,  'v' },
        { "help",     no_argument,       0,  'h' },
        { 0,          0,                 0,   0  }
    };
    const char *substr;
    int opt;

    cmd->window = -1;
    cmd->payload_size = 515;
    cmd->number_of_exchanges = 100;
    cmd->uart_baudrate = 115200;
    strcpy(cmd->uart_device, "/dev/ttyACM0");
    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        switch (opt) {
            case 'u':
                strcpy(cmd->uart_device, optarg);
                break;
            case 'C':
                strcpy(cmd->cpc_instance, optarg);
                break;
            case 'B':
                cmd->uart_baudrate = strtol(optarg, NULL, 10);
                break;
            case 's':
                cmd->payload_size = strtol(optarg, NULL, 10);
                break;
            case 'c':
                cmd->number_of_exchanges = strtol(optarg, NULL, 10);
                break;
            case 'w':
                cmd->window = strtol(optarg, NULL, 10);
                break;
            case 'r':
                cmd->reset = true;
                WARN("-r is not yet supported");
                break;
            case 'q':
                cmd->quiet = true;
                break;
            case 'v':
                cmd->verbose = true;
                break;
            case 'T':
                substr = strtok(optarg, ",");
                do {
                    g_enabled_traces |= str_to_val(substr, valid_traces);
                } while ((substr = strtok(NULL, ",")));
                break;
            case 'h':
                print_help(stdout, 0);
                break;
            case '?':
                print_help(stderr, 1);
                break;
            default:
                break;
        }
    }
    if (optind >= argc)
        FATAL(1, "expected argument: mode");
    if (optind + 1 < argc)
        FATAL(1, "unexpected argument: %s", argv[optind + 1]);
    cmd->mode = str_to_val(argv[optind], accepted_modes);
    if (cmd->window < 0) {
        cmd->window = 2;
        if (cmd->payload_size < 256)
            cmd->window = 10;
        if (cmd->payload_size < 64)
            cmd->window = 20;
        if (cmd->payload_size < 32)
            cmd->window = 40;
        INFO("window size: %d", cmd->window);
    }
    if (cmd->payload_size * cmd->window >= 4096)
        WARN("huge window is selected");
    cmd->payload_size -= 9;
    FATAL_ON(cmd->payload_size < 0, 2, "payload size must > 8");
}

static uint8_t get_spinel_hdr(struct bus *bus)
{
    uint8_t hdr = FIELD_PREP(0xC0, 0x2) | FIELD_PREP(0x30, bus->spinel_iid);

    bus->spinel_tid = (bus->spinel_tid + 1) % 0x10;
    if (!bus->spinel_tid)
        bus->spinel_tid = 1;
    hdr |= FIELD_PREP(0x0F, bus->spinel_tid);
    return hdr;
}

static void send(struct bus *bus, struct commandline_args *cmdline, uint16_t counter, bool is_v2)
{
    struct iobuf_write tx_buf = { };
    uint8_t payload_buf[cmdline->payload_size];

    for (int i = 0; i < cmdline->payload_size; i++)
        payload_buf[i] = i % 0x10;
    if (!is_v2) {
        hif_push_u8(&tx_buf, get_spinel_hdr(bus));
        hif_push_uint(&tx_buf, SPINEL_CMD_RCP_PING);
    } else {
        hif_push_u8(&tx_buf, HIF_CMD_REQ_PING);
    }
    hif_push_u16(&tx_buf, counter);
    if (cmdline->mode & MODE_TX)
        hif_push_u16(&tx_buf, cmdline->payload_size);
    else
        hif_push_u16(&tx_buf, 0);
    if (cmdline->mode & MODE_RX)
        hif_push_raw(&tx_buf, payload_buf, cmdline->payload_size);
    else
        hif_push_raw(&tx_buf, payload_buf, 0);

    if (cmdline->cpc_instance[0])
        cpc_tx(bus, tx_buf.data, tx_buf.len);
    else if (!is_v2)
        uart_legacy_tx(bus, tx_buf.data, tx_buf.len);
    else
        uart_tx(bus, tx_buf.data, tx_buf.len);
    spinel_trace(tx_buf.data, tx_buf.data_size, "hif tx: ");
    iobuf_free(&tx_buf);
}

static size_t read_data(struct bus *bus, struct commandline_args *cmdline, uint8_t *buf, int buf_len, bool is_v2)
{
    int len, ret;
    struct pollfd pollfd = {
        .fd = bus->fd,
        .events = POLLIN,
    };

    do {
        if (!bus->uart.data_ready) {
            ret = poll(&pollfd, 1, 5000); // response time of ping should below 5 second
            if (ret < 0)
                FATAL(2, "poll: %m");
            if (!ret)
                return 0;
        }

        if (pollfd.revents & POLLIN || bus->uart.data_ready) {
            if (cmdline->cpc_instance[0])
                len = cpc_rx(bus, buf, buf_len);
            else if (!is_v2)
                len = uart_legacy_rx(bus, buf, buf_len);
            else
                len = uart_rx(bus, buf, buf_len);
        }
    } while (!len);
    return len;
}

static int receive(struct bus *bus, struct commandline_args *cmdline, uint16_t counter, bool is_v2)
{
    const uint8_t *payload;
    int expected_payload, val;
    uint8_t buffer[4096]; // CPC needs a buffer of 4096
    struct iobuf_read rx_buf = { };

    rx_buf.data = buffer;
    rx_buf.data_size = read_data(bus, cmdline, buffer, sizeof(buffer), is_v2);
    if (!rx_buf.data_size) {
        WARN("poll: no answer from RCP on ping %d", counter);
        return counter + 1;
    }
    if (!is_v2)
        spinel_trace(rx_buf.data, rx_buf.data_size, "hif rx: ");
    val = hif_pop_u8(&rx_buf); // Either RCPv2 command or SPINEL header
    if (is_v2)
        TRACE(TR_HIF, "hif rx: %s %s", hif_cmd_str(val),
              tr_bytes(iobuf_ptr(&rx_buf), iobuf_remaining_size(&rx_buf),
                       NULL, 128, DELIM_SPACE | ELLIPSIS_STAR));

    if (!is_v2) {
        val = hif_pop_uint(&rx_buf);
        if (val != SPINEL_CMD_RCP_PING) {
            if (val == SPINEL_CMD_PROP_IS && hif_pop_uint(&rx_buf) == SPINEL_PROP_WS_RCP_CRC_ERR) {
                WARN("RCP complains it received a CRC error");
                return counter + 1;
            } else {
                WARN("received %02x instead of %02x", val, SPINEL_CMD_RCP_PING);
                return counter;
            }
        }
    } else if (val != HIF_CMD_CNF_PING) {
        WARN("received %02x instead of %02x", val, HIF_CMD_CNF_PING);
        return counter;
    }

    val = hif_pop_u16(&rx_buf);
    if (val != counter)
        WARN("sent ping request %d and received reply %d", counter, val);
    counter = val;

    if (!is_v2) {
        val = hif_pop_u16(&rx_buf);
        if (val != 0)
            WARN("reply size from RCP was not 0");
        val = hif_pop_raw_ptr(&rx_buf, &payload);
    } else {
        val = hif_pop_data_ptr(&rx_buf, &payload);
    }

    if (cmdline->mode & MODE_TX)
        expected_payload = cmdline->payload_size;
    else
        expected_payload = 0;
    if (val != expected_payload)
        WARN("expected %d bytes but received %d bytes", expected_payload, val);

    return counter + 1;
}

static void diff_timespec(struct timespec *ts_start, struct timespec *ts_end, struct timespec *ts_result)
{
    if ((ts_end->tv_nsec - ts_start->tv_nsec) < 0) {
        ts_result->tv_sec = ts_end->tv_sec - ts_start->tv_sec - 1;
        ts_result->tv_nsec = ts_end->tv_nsec - ts_start->tv_nsec + 1000000000;
    } else {
        ts_result->tv_sec = ts_end->tv_sec - ts_start->tv_sec;
        ts_result->tv_nsec = ts_end->tv_nsec - ts_start->tv_nsec;
    }
}

static void print_progress(struct commandline_args *cmdline, int out, int in)
{
    static const char progress[] = { '-', '\\', '|', '/' };
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    if (cmdline->quiet)
        return;
    if (cmdline->verbose)
        INFO("%ld.%06ld: tx:%d rx:%d", ts.tv_sec, ts.tv_nsec / 1000, out, in);
    else
        printf(" %c\r", progress[in % ARRAY_SIZE(progress)]);
    fflush(stdout);
}

static void print_throughput(struct timespec *ts, struct commandline_args *cmdline, bool is_v2)
{
    double real_exchanges_count = cmdline->number_of_exchanges;
    double real_time = ts->tv_sec + ts->tv_nsec / 1000000000.;
    double real_payload;

    if (!is_v2) {
        // 1 hdr + 1 cmd + 2 cnt + 2 reply size + 2 crc + 1 term
        real_payload = cmdline->payload_size + 9;
        if (cmdline->cpc_instance[0])
            WARN("throughput bias due to CPC encoding");
        else
            WARN("throughput bias due to HDLC byte escaping");
    } else {
        // 2 len + 2 fcs + 1 cmd + 2 cnt + 2 reply size + 2 fcs
        real_payload = cmdline->payload_size + 11;
    }

    INFO("throughput: %.0lf bytes/sec", real_payload * real_exchanges_count / real_time);
    INFO("equivalent baudrate: %.0lf bits/sec", 10 * real_payload * real_exchanges_count / real_time);
}

static bool detect_v2(struct bus *bus, struct commandline_args *cmdline)
{
    struct iobuf_write buf = { };
    uint32_t version_api;
    bool is_v2;
    int ret;

    if (cmdline->cpc_instance[0]) {
        version_api = cpc_secondary_app_version(bus);
        return !version_older_than(version_api, 2, 0, 0);
    } else {
        hif_push_u8(&buf, get_spinel_hdr(bus));
        hif_push_uint(&buf, SPINEL_CMD_NOOP);
        uart_legacy_tx(bus, buf.data, buf.len);
        iobuf_free(&buf);

        hif_push_u8(&buf, get_spinel_hdr(bus));
        hif_push_uint(&buf, SPINEL_CMD_RESET);
        uart_legacy_tx(bus, buf.data, buf.len);
        iobuf_free(&buf);

        hif_push_u8(&buf, HIF_CMD_REQ_RESET);
        hif_push_bool(&buf,false);
        uart_tx(bus, buf.data, buf.len);
        iobuf_free(&buf);

        is_v2 = uart_detect_v2(bus);
        if (!is_v2) {
            hif_push_u8(&buf, get_spinel_hdr(bus));
            hif_push_uint(&buf, SPINEL_CMD_NOOP);
            uart_legacy_tx(bus, buf.data, buf.len);
            iobuf_free(&buf);
        }
        bus->uart.data_ready = false;
        bus->uart.rx_buf_len = 0;
        ret = tcflush(bus->fd, TCIFLUSH);
        FATAL_ON(ret < 0, 2, "tcflush: %m");
        return is_v2;
    }
}

static void *sighandler_data;

static void sighandler(int signum)
{
    uart_tx_flush(sighandler_data);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    const struct sigaction sigact = { .sa_handler = sighandler };
    struct timespec ts_start, ts_end, ts_res;
    struct commandline_args cmdline = { };
    struct bus bus = { };
    int in_cnt, out_cnt;
    bool is_v2;

    sighandler_data = &bus;
    sigaction(SIGINT, &sigact, NULL);

    parse_commandline(&cmdline, argc, argv);

    if (cmdline.cpc_instance[0])
        bus.fd = cpc_open(&bus, cmdline.cpc_instance, g_enabled_traces & TR_CPC);
    else
        bus.fd = uart_open(cmdline.uart_device, cmdline.uart_baudrate, false);
    FATAL_ON(bus.fd < 0, 2, "Cannot open device: %m");
    is_v2 = detect_v2(&bus, &cmdline);

    out_cnt = 0;
    in_cnt = 0;
    while (out_cnt < cmdline.window) {
        send(&bus, &cmdline, out_cnt, is_v2);
        print_progress(&cmdline, out_cnt, in_cnt);
        out_cnt++;
    }
    clock_gettime(CLOCK_REALTIME, &ts_start);
    while (out_cnt < cmdline.number_of_exchanges + cmdline.window) {
        while (out_cnt <= in_cnt + cmdline.window) {
            send(&bus, &cmdline, out_cnt, is_v2);
            print_progress(&cmdline, out_cnt, in_cnt);
            out_cnt++;
        }
        in_cnt = receive(&bus, &cmdline, in_cnt, is_v2);
    }
    clock_gettime(CLOCK_REALTIME, &ts_end);
    while (in_cnt < out_cnt) {
        in_cnt = receive(&bus, &cmdline, in_cnt, is_v2);
        print_progress(&cmdline, out_cnt, in_cnt);
    }

    diff_timespec(&ts_start, &ts_end, &ts_res);
    print_throughput(&ts_res, &cmdline, is_v2);

    return 0;
}

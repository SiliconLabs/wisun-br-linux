/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <pty.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "log.h"
#include "mux.h"
#include "utils.h"
#include "bus_spi.h"
#include "bus_uart.h"

void rx_bus(struct mux_ctxt *ctxt)
{
    char buf[256];
    int len, i;

    len = ctxt->rx_bus(ctxt, buf, sizeof(buf));
    if (len <= 0)
        FATAL(2, "reach EOF?");
    for (i = 0; i < ARRAY_SIZE(ctxt->clients); i++)
        if (ctxt->clients[i] > 0)
            write(ctxt->clients[i], buf, len);
}

static void rx_client(struct mux_ctxt *ctxt, int socket)
{
    char buf[256];
    int len, i;

    len = read(socket, buf, sizeof(buf));
    if (len <= 0) {
        printf("closed connection\n");
        for (i = 0; i < ARRAY_SIZE(ctxt->clients); i++) {
            if (ctxt->clients[i] == socket) {
                close(socket);
                ctxt->clients[i] = 0;
            }
        }
    }
    ctxt->tx_bus(ctxt, buf, len);
}

static void rx_new_connection(struct mux_ctxt *ctxt)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(ctxt->clients); i++) {
        if (!ctxt->clients[i]) {
            ctxt->clients[i] = accept(ctxt->fd_sock, NULL, NULL);
            printf("incoming connection\n");
            return;
        }
    }
    WARN("no more available connexion");
}

void process_event(struct mux_ctxt *ctxt)
{
    fd_set rfds;
    int max_fd = 0;
    int ret, i;

    FD_ZERO(&rfds);
    FD_SET(ctxt->fd_trig, &rfds);
    max_fd = max(max_fd, ctxt->fd_trig);
    if (ctxt->fd_sock) {
        FD_SET(ctxt->fd_sock, &rfds);
        max_fd = max(max_fd, ctxt->fd_sock);
    }
    for (i = 0; i < ARRAY_SIZE(ctxt->clients); i++) {
        if (ctxt->clients[i] > 0) {
            FD_SET(ctxt->clients[i] , &rfds);
            max_fd = max(max_fd, ctxt->clients[i]);
        }
    }
    ret = pselect(max_fd + 1, &rfds, NULL, NULL, NULL, NULL);
    BUG_ON(ret < 0);
    if (FD_ISSET(ctxt->fd_sock, &rfds))
        rx_new_connection(ctxt);
    if (FD_ISSET(ctxt->fd_trig, &rfds))
        rx_bus(ctxt);
    for (i = 0; i < ARRAY_SIZE(ctxt->clients); i++)
        if (FD_ISSET(ctxt->clients[i], &rfds))
            rx_client(ctxt, ctxt->clients[i]);
}

static void create_socket(struct mux_ctxt *ctxt, char *file)
{
    struct sockaddr_un addr = {
        .sun_family = AF_UNIX
    };

    strncpy(addr.sun_path, file, sizeof(addr.sun_path));
    unlink(addr.sun_path);
    ctxt->fd_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctxt->fd_sock < 0)
        FATAL(2, "socket: %m");
    if (bind(ctxt->fd_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        FATAL(2, "bind: %m");
    if (listen(ctxt->fd_sock, 3) < 0)
        FATAL(2, "listen: %m");
}

static void create_pty(struct mux_ctxt *ctxt, char *link)
{
    struct termios tty;
    char pty_name[256];
    int fd_slave;
    int i;

    for (i = 0; i < ARRAY_SIZE(ctxt->clients); i++)
        if (!ctxt->clients[i])
            break;
    if (i == ARRAY_SIZE(ctxt->clients))
        FATAL(2, "too much requested ptys");

    if (openpty(&ctxt->clients[i], &fd_slave, pty_name, NULL, NULL) < 0)
        FATAL(1, "openpty: %m");
    if (tcgetattr(ctxt->clients[i], &tty) < 0)
        FATAL(1, "tcgetattr: %m");
    cfmakeraw(&tty);
    if (tcsetattr(ctxt->clients[i], TCSAFLUSH, &tty) < 0)
        FATAL(1, "tcsetattr: %m");
    unlink(link);
    if (symlink(pty_name, link) < 0)
        FATAL(1, "symlink: %m");
}

void print_help(FILE *stream, int exit_code) {
    fprintf(stream, "Start MUX daemon on UART or SPI device\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  muxd -u [OPTIONS] UART_DEVICE\n");
    fprintf(stream, "  muxd -s [OPTIONS] SPI_DEVICE GPIO_FILE\n");
    fprintf(stream, "  muxd -s [OPTIONS] SPI_DEVICE GPIO_NUMBER\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -u                     Use UART bus\n");
    fprintf(stream, "  -s                     Use SPI bus\n");
    fprintf(stream, "  -U, --unix-socket=FILE Listen on socket FILE for a connection\n");
    fprintf(stream, "  -p, --pty=FILE         Open a new pty and make it a symlink to FILE\n");
    fprintf(stream, "\n");
    fprintf(stream, "UART options\n");
    fprintf(stream, "  -b, --baudrate=BAUDRATE  UART baudrate: 9600,19200,38400,57600,115200 (default),230400,460800,921600\n");
    fprintf(stream, "  -H, --hardflow           Hardware CTS/RTS flow control (default disabled)\n");
    fprintf(stream, "\n");
    fprintf(stream, "SPI options:\n");
    fprintf(stream, "  -f, --frequency=FREQUENCY  Clock frequency (default 1000000)\n");
    fprintf(stream, "\n");
    fprintf(stream, "Exemples:\n");
    fprintf(stream, "  mux -u /dev/ttyUSB0 -H -U /run/mux/socket\n");
    fprintf(stream, "  mux -s /dev/spi1.1 141 -U /tmp/socket -p /tmp/pty1 -p /tmp/pty2\n");
    fprintf(stream, "  mux -s /dev/spi1.1 /sys/class/gpio/gpio141/value -p /tmp/pty\n");
    exit(exit_code);
}

void configure(struct mux_ctxt *ctxt, int argc, char *argv[])
{
    static const struct option opt_list[] = {
        { "help",        no_argument,       0,  'h' },
        { "baudrate",    required_argument, 0,  'b' },
        { "hardflow",    no_argument,       0,  'H' },
        { "frequency",   required_argument, 0,  'f' },
        { "unix-socket", required_argument, 0,  'U' },
        { "pty",         required_argument, 0,  'p' },
        { 0,             0,                 0,   0  }
    };
    char *end_ptr;
    char bus = 0;
    int baudrate = 115200;
    int frequency = 1000000;
    bool hardflow = false;
    int opt;

    while ((opt = getopt_long(argc, argv, "usf:Hb:hU:p:", opt_list, NULL)) != -1) {
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
            case 'U':
                if (ctxt->fd_sock)
                    FATAL(1, "-U can be specified only once");
                create_socket(ctxt, optarg);
                break;
            case 'p':
                create_pty(ctxt, optarg);
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
    if (!ctxt->fd_sock && !ctxt->clients[0])
        FATAL(1, "-U or -p must be specified");
    if (bus == 's') {
        if (argc != optind + 2)
            print_help(stderr, 1);
        ctxt->tx_bus = mux_spi_tx;
        ctxt->rx_bus = mux_spi_rx;
        ctxt->fd_bus = mux_spi_open(argv[optind + 0], frequency, 0);
        ctxt->fd_trig = mux_gpio_open(argv[optind + 1], false);
    } else if (bus == 'u') {
        if (argc != optind + 1)
            print_help(stderr, 1);
        ctxt->tx_bus = mux_uart_tx;
        ctxt->rx_bus = mux_uart_rx;
        ctxt->fd_bus = mux_uart_open(argv[optind + 0], baudrate, hardflow);
        ctxt->fd_trig = ctxt->fd_bus;
    } else {
        print_help(stderr, 1);
    }
}

int main(int argc, char *argv[])
{
    struct mux_ctxt ctxt = { };

    signal(SIGPIPE, SIG_IGN);
    configure(&ctxt, argc, argv);
    for (;;)
        process_event(&ctxt);
    return 0;
}


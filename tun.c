/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>

#include "platform/arm_hal_phy.h"
#include "ethernet_mac_api.h"
#include "net_interface.h"

#include "tun.h"
#include "log.h"
#include "wsbr.h"

static int8_t wsbr_tun_tx(uint8_t *buf, uint16_t len, uint8_t tx_handle, data_protocol_e protocol)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    int ret;

    ret = write(ctxt->tun_fd, buf, len);
    WARN_ON(ret != len);
    return 0;
}

static uint8_t tun_mac[8] = { 20, 21, 22, 23, 24, 25, 26, 27 };
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
    .tx = wsbr_tun_tx,
};

static int wsbr_tun_open(char *devname)
{
    struct rtnl_link *link;
    struct nl_sock *sock;
    struct ifreq ifr = {
        .ifr_flags = IFF_TUN,
    };
    int fd, ifindex;

    if (devname && *devname)
        strcpy(ifr.ifr_name, devname);
    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
        FATAL(2, "tun open: %m");
    if (ioctl(fd, TUNSETIFF, &ifr))
        FATAL(2, "tun ioctl: %m");
    if (devname)
        strcpy(devname, ifr.ifr_name);
    sock = nl_socket_alloc();
    if (nl_connect(sock, NETLINK_ROUTE))
        FATAL(2, "nl_connect");
    if (rtnl_link_get_kernel(sock, 0, ifr.ifr_name, &link))
        FATAL(2, "rtnl_link_get_kernel %s", ifr.ifr_name);
    if (rtnl_link_get_operstate(link) != IF_OPER_UP ||
        !(rtnl_link_get_flags(link) & IFF_UP)) {
        ifindex = rtnl_link_get_ifindex(link);
        rtnl_link_put(link);
        link = rtnl_link_alloc();
        rtnl_link_set_ifindex(link, ifindex);
        rtnl_link_set_operstate(link, IF_OPER_UP);
        rtnl_link_set_flags(link, IFF_UP);
        if (rtnl_link_add(sock, link, 0))
            FATAL(2, "rtnl_link_add %s", ifr.ifr_name);
        rtnl_link_put(link);
    } else {
        rtnl_link_put(link);
    }
    nl_socket_free(sock);
    return fd;
}

void wsbr_tun_init(struct wsbr_ctxt *ctxt)
{
    ctxt->tun_fd = wsbr_tun_open(ctxt->tun_dev);

    ctxt->tun_driver = &tun_driver;
    ctxt->tun_driver_id = arm_net_phy_register(ctxt->tun_driver);
    if (ctxt->tun_driver_id < 0)
        FATAL(2, "%s: arm_net_phy_register: %d", __func__, ctxt->tun_driver_id);
    ctxt->tun_mac_api = ethernet_mac_create(ctxt->tun_driver_id);
    if (!ctxt->tun_mac_api)
        FATAL(2, "%s: ethernet_mac_create", __func__);
    ctxt->tun_if_id = arm_nwk_interface_ethernet_init(ctxt->tun_mac_api, "bh0");
    if (ctxt->tun_if_id < 0)
        FATAL(2, "%s: arm_nwk_interface_ethernet_init: %d", __func__, ctxt->tun_if_id);
}

void wsbr_tun_read(struct wsbr_ctxt *ctxt)
{
    char buf[1504]; // Max ethernet frame size + TUN header
    int len;

    len = read(ctxt->tun_fd, buf, sizeof(buf));
    ctxt->tun_driver->phy_rx_cb(buf, len, 0x80, 0, ctxt->tun_driver_id);
}


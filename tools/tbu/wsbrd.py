#
# SPDX-License-Identifier: LicenseRef-MSLA
# Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
#
# The licensor of this software is Silicon Laboratories Inc. Your use of this
# software is governed by the terms of the Silicon Labs Master Software License
# Agreement (MSLA) available at [1].  This software is distributed to you in
# Object Code format and/or Source Code format and is governed by the sections
# of the MSLA applicable to Object Code, Source Code and Modified Open Source
# Code. By using this software, you agree to the terms of the MSLA.
#
# [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
#
import sdbus
import typing


TMPDIR = '/tmp/wstbu'

# wsbrd SetLinkModeSwitch DBUS API
WSBRD_MODE_SWITCH_DEFAULT  = 0
WSBRD_MODE_SWITCH_DISABLED = 1
WSBRD_MODE_SWITCH_PHY      = 2
WSBRD_MODE_SWITCH_MAC      = 3

# wsbrd SetLinkEDFE DBUS API
WSBRD_EDFE_DEFAULT  = 0
WSBRD_EDFE_DISABLED = 1
WSBRD_EDFE_ENABLED  = 2

config: dict[str, typing.Any] = dict()


def config_default(wstbu_config):
    config = dict(
        uart_device    = wstbu_config['uart_device'],
        tun_device     = 'tunwstbu',
        ipv6_prefix    = wstbu_config['ipv6_prefix'],
        size           = 'CERT',
        enable_lfn     = False,
        enable_ffn10   = True,
        storage_prefix = TMPDIR + '/nvm/',
        fan_version    = wstbu_config['fan_version'],
        gtk_new_install_required  = 0,
        lgtk_new_install_required = 0,
        pcap_file      = TMPDIR + '/fifo.pcap',
        join_metrics   = 'none',
        trace          = '15.4,eap,icmp,dhcp,drop',
    )
    if 'dhcpv6_server' in wstbu_config:
        config['dhcp_server'] = wstbu_config['dhcpv6_server']
    if 'radius_server' in wstbu_config:
        config['radius_server'] = wstbu_config['radius_server']
    if 'radius_secret' in wstbu_config:
        config['radius_secret'] = wstbu_config['radius_secret']
    return config


class SystemdUnitDbusInterface(
    sdbus.DbusInterfaceCommon,
    interface_name='org.freedesktop.systemd1.Unit'
):
    @sdbus.dbus_method('s', 'o')
    def start(self, mode: str) -> str:
        raise NotImplementedError

    @sdbus.dbus_method('s', 'o')
    def stop(self, mode: str) -> str:
        raise NotImplementedError

    @sdbus.dbus_property('s')
    def active_state(self) -> str:
        raise NotImplementedError


service = SystemdUnitDbusInterface(
    bus=sdbus.sd_bus_open_system(),
    service_name='org.freedesktop.systemd1',
    object_path=sdbus.encode_object_path('/org/freedesktop/systemd1/unit', 'wisun-borderrouter.service'),
)


class WsbrdDbusInterface(
    sdbus.DbusInterfaceCommon,
    interface_name='com.silabs.Wisun.BorderRouter'
):
    @sdbus.dbus_property('aay')
    def gtks(self) -> list[bytes]:
        raise NotImplementedError

    @sdbus.dbus_property('aay')
    def lgtks(self) -> list[bytes]:
        raise NotImplementedError

    @sdbus.dbus_property('a(aya{sv})')
    def nodes(self) -> list[tuple[bytes, dict[str, tuple[str, typing.Any]]]]:
        raise NotImplementedError

    @sdbus.dbus_property('a(aybaay)')
    def routing_graph(self) -> list[tuple[bytes, bool, list[bytes]]]:
        raise NotImplementedError

    @sdbus.dbus_method('ayuy')
    def set_link_mode_switch(self, eui64: bytes, phy_mode_id: int, ms_mode: int) -> None:
        raise NotImplementedError

    @sdbus.dbus_method('ayy')
    def set_link_edfe(self, eui64: bytes, ms_mode: int) -> None:
        raise NotImplementedError

    @sdbus.dbus_method('ay')
    def join_multicast_group(self, addr: bytes) -> None:
        raise NotImplementedError

    @sdbus.dbus_method('ay')
    def leave_multicast_group(self, addr: bytes) -> None:
        raise NotImplementedError

    @sdbus.dbus_method('ayay')
    def revoke_group_keys(self, gtk: bytes, lgtk: bytes) -> None:
        raise NotImplementedError

    @sdbus.dbus_method('ay')
    def install_gtk(self, gtk: bytes) -> None:
        raise NotImplementedError

    @sdbus.dbus_method('ay')
    def install_lgtk(self, lgtk: bytes) -> None:
        raise NotImplementedError

    @sdbus.dbus_method('yyayay')
    def ie_custom_insert(self, ie_type, id, content, frame_types) -> None:
        raise NotImplementedError

    @sdbus.dbus_method()
    def ie_custom_clear(self) -> None:
        raise NotImplementedError

    @sdbus.dbus_method()
    def increment_rpl_dtsn(self) -> None:
        raise NotImplementedError

    @sdbus.dbus_method()
    def increment_rpl_dodag_version_number(self) -> None:
        raise NotImplementedError

    @sdbus.dbus_method('aay')
    def allow_mac64(self, eui64: list[bytes]) -> None:
        raise NotImplementedError

# For some reason, storing an instance of WsbrdDbusInterface in a global
# variable (as for SystemdUnitDbusInterface) results in the error 'Transport
# endpoint is not connected' when trying to access D-Bus attributes or methods.
# Creating a new instance every time seems to work.
def dbus():
    return WsbrdDbusInterface(
        bus=sdbus.sd_bus_open_system(),
        service_name='com.silabs.Wisun.BorderRouter',
        object_path='/com/silabs/Wisun/BorderRouter',
    )

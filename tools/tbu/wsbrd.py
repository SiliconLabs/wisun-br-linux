import sdbus
import typing


config = None


def config_default(wstbu_config):
    config = dict(
        uart_device    = wstbu_config.uart_device,
        tun_device     = wstbu_config.tun_device,
        ipv6_prefix    = wstbu_config.ipv6_prefix,
        size           = 'CERT',
        enable_lfn     = False,
        enable_ffn10   = True,
        internal_dhcp  = 'n',
        storage_prefix = wstbu_config.nvm_dir,
        fan_version    = wstbu_config.fan_version,
        gtk_new_install_required  = 0,
        lgtk_new_install_required = 0,
        pcap_file      = wstbu_config.fifo_path,
        join_metrics   = 'none',
        trace          = '15.4,eap,icmp,dhcp,drop',
    )
    if wstbu_config.radius_server:
        config['radius_server'] = wstbu_config.radius_server
    if wstbu_config.radius_secret:
        config['radius_secret'] = wstbu_config.radius_secret
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

    @sdbus.dbus_method('ayi')
    def set_mode_switch(self, eui64: bytes, phy_mode_id: int) -> None:
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
    def increment_rpl_dtsn(self) -> None:
        raise NotImplementedError

    @sdbus.dbus_method()
    def increment_rpl_dodag_version_number(self) -> None:
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

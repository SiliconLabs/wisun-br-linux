<table border="0">
  <tr>
    <td align="left" valign="middle">
    <h1>Wi-SUN Linux Border Router</h1>
  </td>
  <td align="left" valign="middle">
    <a href="https://wi-sun.org/">
      <img src="misc/wisun-logo.png" title="Wi-SUN" alt="Wi-SUN Logo" width="300"/>
    </a>
  </td>
  </tr>
</table>

The goal of this project is to implement the Wi-SUN protocol on Linux devices
and allow the use of Linux hosts as Border Router for Wi-SUN networks. For the
time being, the implementation is mostly a port of Silicon Labs' embedded stack
on a Linux host. However, the ultimate goal is to replace services currently
provided by the stack with native Linux services.

# Quick Start Guide

## Prerequisites

This project provides the `wsbrd` daemon, which is responsible for running the
Wi-SUN protocol high-level layers. It is paired with an RF device RCP (Radio
Co-Processor) handling the low-level layers and RF activities. The RCP devices
currently supported are the EFR32FG12 and EFR32MG12.

The RCP needs to be flashed with a specific firmware to communicate with the
daemon. This firmware is provided in binary format. To help users deploy and
evaluate the solution, a [wisun-br-linux-docker][1] repository is provided. It
contains a bundle of all the necessary software components (including a
compiled RCP firmware) to run the Linux Wi-SUN border router.

Alternatively, [Application Note 1332][2] explains how to build RCP firmware and
flash it.

The communication between the Linux host and the RCP is supported through a
serial link (UART). On Silicon Labs mainboards, this serial link is provided
over USB. The `/dev/ACMx` device should appear when you connect the mainboard.

[1]: https://github.com/SiliconLabs/wisun-br-linux-docker
[2]: https://www.silabs.com/documents/public/application-notes/an1332-wi-sun-network-configuration.pdf

## Cloning wisun-br-linux

If it is not yet done, start by cloning this repository:

    git clone https://github.com/SiliconLabs/wisun-br-linux.git

## Compiling

The build requires `mbedTLS` (> 2.18), `libnl-3`, `libnl-route-3`, `cmake`.
`libsystemd` is also recommended (note that it can be replaced by `elogind` if
you don't want to pull `systemd`). Optionally, you can also install `libpcap`
and Rust/Cargo.

We also encourage the use of Ninja as the `cmake` back-end.

On Debian and its derivatives, install the necessary dependencies (except for
mbedTLS) with:

    sudo apt-get install libnl-3-dev libnl-route-3-dev libpcap-dev libsystemd-dev cargo cmake ninja-build

Debian does not (yet) package `mbedTLS` > 2.18 so you must build it from
sources. Note that support for `cmake` has been added to `mbedTLS` 2.27. So, if
you want to use `mbedTLS` < 2.27, the following process does not work. In
addition, since `wsbrd` is mainly tested with `mbedTLS` 3.0, we suggest using
this version.

    git clone --branch=v3.0.0 https://github.com/ARMmbed/mbedtls
    cd mbedtls
    cmake -G Ninja .
    ninja
    sudo ninja install

`MbedTLS` is highly customizable. The default configuration is sane. However, if
you want a stripped-down version, you can configure it with the configuration
file provided in `examples/mbedtls-config.h`:

    CFLAGS="-I$FULL_PATH_TO_WSBRD_SRC/examples -DMBEDTLS_CONFIG_FILE='<mbedtls-config.h>'" cmake -G Ninja .

> This configuration file has been written for `mbedtls` 3.0. Adapt it if
> necessary.

Then, you can compile `wsbrd` with:

    cd wisun-br-linux/
    cmake -G Ninja .
    ninja

Finally, install the service with:

    sudo ninja install

> No script for any start-up service is provided for now.

## Launching

You must provide a configuration file to the Wi-SUN border router. A
commented example is available in `/usr/local/share/doc/wsbrd/examples/wsbrd.conf`.

    cp -r /usr/local/share/doc/wsbrd/examples .
    <edit examples/wsbrd.conf>

You can copy and edit it. You will notice that you need certificates and keys to
authenticate your network's Wi-SUN nodes. The generation of these files is
described in [[Generate Wi-SUN PKI]].  For now, you can use the certificates
examples installed in `/usr/local/share/doc/wsbrd/examples/`.

You also must provide the path of the UART representing your RCP device.

Finally, launch `wsbrd` with:

    sudo wsbrd -F examples/wsbrd.conf -u /dev/ttyACM0

`wsbrd` lists the useful options in the output of `wsbrd --help`.

# Using the DBus Interface

`wsbrd` provides a DBus interface. You can use a generic DBus tool like
[`busctl`][3] to communicate with `wsbrd`. Typically, the following command
gives an overview of the DBus interface:

    busctl introspect com.silabs.Wisun.BorderRouter /com/silabs/Wisun/BorderRouter

DBus bindings are available in [all][4] [common][5] [languages][6].

[3]: https://www.freedesktop.org/software/systemd/man/busctl.html
[4]: https://www.freedesktop.org/software/systemd/man/sd-bus.html
[5]: https://python-sdbus.readthedocs.io/
[6]: https://www.npmjs.com/package/dbus-next

# Generating the Wi-SUN Public Key Infrastructure

The certificate generation process is described in section 6.5.1 of the Wi-SUN
specification. It uses the standard X.509 certificate format. Some fields and
algorithms are enforced.

The process to get official certificates is described on the [Wi-SUN alliance
Web site][7] (restricted access).

[7]: https://wi-sun.org/cyber-security-certificates/

# Running your dhcp server on the same host as `wsbrd`

If you choose to run your dhcp server on the same host as `wsbrd` you will have
to create a tap interface:

    sudo ip tuntap add mode tap tap0

You also have to give this interface an address in the subnet you have
configured on your dhcp server:

    sudo ip addr add 2001:db8::1 dev tap0

In order to prevent packets with an MTU of more than 1280 bytes from going 
on the Wi-SUN network:

    sudo ip link set mtu 1280 dev tap0

Bring up the interface, this will add a route to the Wi-SUN network:

    sudo ip link set up dev tap0

If you have `tun_autoconf` set to `false` in your `wsbrd.conf`:

    sudo sysctl net.ipv6.conf.tap0.accept_ra=0

Copy the example configuration:

    sudo cp examples/dhcpd.conf /etc/dhcp/dhcpd.conf

Start your DHCP server:

    sudo sytemctl start dhcpd6.service

Configure `wsbrd` to use a tap interface named `tap0`:

    tun_device = tun0
    use_tap = false

Launch `wsbrd`.

# Running `wsbrd` without Root Privileges

It is possible to launch `wsbrd` without root privileges. First, ensure you have
permission to access the UART device:

    sudo usermod -aG dialout YOUR_USER

> You must logout/login after this step

Create a tun interface:

    sudo ip tuntap add mode tun tun0 user YOUR_USER

Start `wsbrd`:

    wsbrd -F examples/wsbrd.conf -t tun0 -u /dev/ttyACM0

# Bugs and Limitations

## Should I use CPC and plain UART?

CPC protocol relies on an external service (CPCd). So plain UART allows an
easier integration for simple setups. However, CPC offers some features:

  - support for SPI bus
  - support for encrypted link with the RCP
  - support for Dynamic MultiProtocol (DMP). Thus, CPCd can share the RCP
    between several network stacks (ie. Bluetooth, Zigbee, OpenThread and
    Wi-SUN)


## Hidden Internal Network Interfaces

The network interface presented on the Linux side is not directly linked to the
RF interface. Instead, `wsbrd` sees the Linux interface as a backhaul and the RF
as a separate interface.

Therefore, you can encounter three interfaces with their own MAC and IPv6
addresses:

  - The Linux interface as displayed by `ip link`
  - The other side of the Linux interface seen by `wsbrd` (called the backhaul
    interface)
  - The RF interface

This is mostly invisible for the end-user. However, an attentive user may notice
small details:

  - The DODAGID does not match the IP of the Linux interface.
  - The origin of RPL frames does not match the IP of the Linux interface.
  - The IPv6 hop-limit (formerly known as TTL in IPv4) field is decremented.
  - Direct consequence of the previous item: packets with a hop-limit of 1 are
    not forwarded to the Wi-SUN network. Typically, to ping a multicast address,
    you have to enforce the hop-limit to at least 2:

    ping -t 2 -I tun0 ff03::fc

  - Multicast link-local frames (typically Router Solicitations and Router
    Advertisements) are not forwarded to the Wi-SUN network. These frames would
    be ignored in the Wi-SUN network anyway.

When no DHCP is server is in use, the IP addresses of the interfaces are
configured in this order:

    1. The address of the backhaul interface is generated from `ipv6_prefix`.
       Then wsbrd starts the internal DHCP server and starts to advertise
       `ipv6_prefix` on the Linux interface
    2. Thank to advertisements, the Linux interface can use SLAAC to get an IP.
    3. The RF interface request a IP from the internal DHCP server

When using an external DHCP server:

    1. The IP of the Linux interface is set by the user
    2. The backhaul interface get its IP from the prefix of the DHCP server
       address
    3. The RF interface request a IP from the external DHCP server

## I cannot connect to DBus interface

There are several DBus instances on your system:
  - One system instance
  - An instance for each user

By default, `wsbrd` tries to use the `user` instance and falls back to `system`
instance.

The DBus session used is shown in the first lines of the log output:

    Successfully registered to system DBus

Then, use `busctl --system` or `busctl --user` accordingly.

Note that if you use `sudo` to launch `wsbrd` as root user, it will use the
`system` instance.

You can enforce the session used with an environment variable
`DBUS_STARTER_BUS_TYPE=system` or `DBUS_STARTER_BUS_TYPE=user`. If you use
`sudo`, you must define this variable inside the `sudo` environment:

    sudo env DBUS_STARTER_BUS_TYPE=system wsbrd ...

## I have issues when trying to send UDP data

Path MTU Discovery works as expected on the Wi-SUN network. The Border Router
replies with `ICMPv6/Packet Too Big` if necessary. (Remember that in IPv6,
routers cannot fragment packets, therefore the sender is responsible of the size
of the packet). Direct neighbors of the Border Router can receive frames up to
1504 bytes, while the other nodes can receive frames up to 1280 bytes.

If you try to send a UDP frame larger than the MTU, there are two
options:

  - The packet has been sent with `IPV6_DONTFRAG`, and the operating system will
    return an error.
  - The packet is not marked with `IPV6_DONTFRAG`, and the operating system will
    fragment the packet.

On the receiver, the buffer must be large enough (up to 64 kB) to handle the
fragmented packet. This feature is sometimes limited on embedded devices.
Typically, on Silicon Labs nodes, the default fragmentation buffer size is 1504
bytes.

Therefore, if you send a buffer greater than 1504 bytes (including IP and MAC
headers), the packet will be silently dropped.

As another consequence, the commonly used tool `nc` cannot be used with Wi-SUN
networks. Indeed, `nc` sends 16 kB-long UDP frames. There is no option to reduce
frame size (or to enable `IPV6_DONTFRAG`).

Therefore, sending UDP packets with `IPV6_DONTFRAG` is recommended. Use
`IPV6_PATHMTU` and `IPV6_RECVPATHMTU` to determine the optimal packet size.

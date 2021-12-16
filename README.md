<table border="0">
  <tr>
    <td align="left" valign="middle">
    <h1>Wi-SUN Linux Border Router</h1>
  </td>
  <td align="left" valign="middle">
    <a href="https://wi-sun.org/">
      <img src="pics/Wi-SUN-logo.png" title="Wi-SUN" alt="Wi-SUN Logo" width="300"/>
    </a>
  </td>
  </tr>
</table>

This project aims at implementing the Wi-SUN protocol on Linux devices and
allowing the use of Linux hosts as Border Router for Wi-SUN networks. For the
time being, the implementation is mostly a port of Silicon Labs embedded stack
on a Linux host. However, the ultimate goal is to replace services currently
provided by the stack with native Linux services.

# Quick Start Guide

## Prerequisites

This project provides the `wsbrd` daemon which is responsible for running the
Wi-SUN protocol high-level layers. It is paired with an RF device RCP (Radio
Co-Processor) handling the low-level layers and RF activities. The RCP devices
currently supported are the EFR32FG12 and EFR32MG12.

The RCP needs to be flashed with a specific firmware to communicate with the
daemon. This firmware is provided in binary format. To help users deploy and
evaluate the solution, a [wisun-br-linux-docker][1] repository is provided. It
contains a bundle of all the necessary software components (including a compiled
RCP firmware) to run the Linux Wi-SUN border router.

The communication between the Linux host and the RCP is supported through a
serial link (UART). On Silicon Labs mainboards, this serial link is provided
over USB. The `/dev/ACMx` device should appear when you plug the mainboard.

[1]: https://github.com/SiliconLabs/wisun-br-linux-docker

## Cloning wisun-br-linux

If it is not yet done, start by cloning his repository:

    git clone git@github.com:SiliconLabs/wisun-br-linux.git

## Compiling

The build requires `libnl-3-dev`, `libnl-route-3-dev`, `cmake`. It is also
recommended to have `libsystemd` (note that it can be replaced by `elogind` if
you don't want to pull `systemd`). Optionally, you can also install `libpcap`.

We also encourage the use of Ninja as `cmake` back-end.

On Debian and its derivatives, install the necessary dependencies with:

    sudo apt-get install libnl-3-dev libnl-route-3-dev libpcap-dev libsystemd-dev cmake ninja-build

Then, compile with:

    cd wisun-br-linux/
    cmake -G Ninja .
    ninja

Finally, install the service with:

    sudo ninja install

> No script for any start-up service is provided for now.

## Launching

You have to provide a configuration file to the Wi-SUN border router. A
commented example is available in `/usr/local/share/doc/wsbrd/examples/wsbrd.conf`.

    cp -r /usr/local/share/doc/wsbrd/examples .
    <edit examples/wsbrd.conf>

You can copy and edit it. You will notice that you need certificates and keys to
authenticate the Wi-SUN nodes of your network. The generation of these files is
described in [[Generate Wi-SUN PKI]].  For now, you can use the certificates
examples installed in `/usr/local/share/doc/wsbrd/examples/`.

You will also need to provide the path of the UART representing your RCP
device.

Finally, you will launch `wsbrd` with:

    sudo wsbrd -F examples/wsbrd.conf -u /dev/ttyACM0

`wsbrd` lists the useful options in the output of `wsbrd --help`.

# Using the DBus interface

`wsbrd` provides a DBus interface. You can use a generic DBus tool like
[`busctl`][3] to communicate with `wsbrd`. Typically, the command below gives an
overview of the DBus interface:

    busctl introspect com.silabs.Wisun.BorderRouter /com/silabs/Wisun/BorderRouter

DBus bindings are available in [all][4] [common][5] [languages][6].

[3]: https://www.freedesktop.org/software/systemd/man/busctl.html
[4]: https://www.freedesktop.org/software/systemd/man/sd-bus.html
[5]: https://python-sdbus.readthedocs.io/
[6]: https://www.npmjs.com/package/dbus-next

# Generate Wi-SUN Public Key Infrastructure

The certificate generation process is described in section 6.5.1 of the Wi-SUN
specification. It uses the standard X.509 certificate format. Some fields and
algorithms are enforced.

The process to get official certificates is described on the [Wi-SUN alliance
Web site][2] (restricted access).

[2]: https://wi-sun.org/cyber-security-certificates/

# Running `wsbrd` without Root Privileges

It is possible to launch `wsbrd` without root privileges. First, ensure you have
the permission to access the UART device:

    sudo usermod -d dialout YOUR_USER

> You have to logout/login after this step

Create a tun interface:

    sudo ip tuntap add mode tun tun0 user YOUR_USER

Start `wsbrd`:

    wsbrd -F examples/wsbrd.conf -t tun0 -u /dev/ttyACM0

# Bugs and Limitations

## Hidden internal network interfaces

The network interface presented on the Linux side is not directly linked to the
RF interface. Instead, `wsbrd` sees the Linux interface as a backhaul and the RF
as a separate interface.

So, you can encounter three interfaces with their own MAC and IPv6 addresses:
  - The Linux interface as displayed by `ip link`
  - The other side of the Linux interface seen by `wsbrd` (called the backhaul
    interface)
  - The RF interface

This is mostly invisible for the end-user. However, an attentive user may notice
small details:
  - The DODAGID does not match the IP of the Linux interface
  - The origin of RPL frames does not match the IP of the Linux interface
  - The IPv6 hop-limit (formerly known as TTL in IPv4) field is decremented
  - Direct consequence of the previous item: packets with a hop-limit of 1 are
    not forwarded to the Wi-SUN network. Typically, to ping a multicast address,
    you have to enforce the hop-limit to at least 2

    ping -t 2 -I tun0 ff03::fc

  - Multicast link-local frames (typically Router Solicitations and Router
    Advertisements) are not forwarded to the Wi-SUN network. These frames would
    be ignored in the Wi-SUN network anyway.

## I cannot connect to DBus interface

You have to know there are several DBus instances on your system:
  - One system instance
  - Each user also has an instance

By default, `wsbrd` tries to use the `user` instance and falls back to `system`
instance.

You can check the DBus session used in the first lines of the log output:

    Successfully registered to system DBus

Then, use `busctl --system` or `busctl --user` accordingly.

Note, that If you use `sudo` to launch `wsbrd` as root user, it will use the
`system` instance.

You can enforce the session used with an environment variable
`DBUS_STARTER_BUS_TYPE=system` or `DBUS_STARTER_BUS_TYPE=user`. If you use
`sudo`, you have to define this variable inside the `sudo` environment:

    sudo env DBUS_STARTER_BUS_TYPE=system wsbrd ...

## I have issues when trying to send UDP data

Path MTU Discovery works as expected on the Wi-SUN network. The Border Router
replies with `ICMPv6/Packet Too Big` if necessary (keep in minds that IPv6,
routers can't fragment packets, sender is responsible of the size of the
packet). Direct neighbors of the Border Router can receive frames up to 1504
bytes while the other nodes can receive frames up to 1280 bytes.

If the user tries to send a UDP frame larger than the MTU, there are two
options:
  - The packet has been sent with `IPV6_DONTFRAG`, the operating system will
    return an error
  - The packet is not marked with `IPV6_DONTFRAG`, the operating system will
    fragment the packet

On the receiver, a large enough (up to 64kB) buffer is necessary to handle
the fragmented packet. So, this feature is sometimes limited on embedded
devices. Typically, on Silicon Labs nodes, the default fragmentation buffer
size is 1504 bytes.

Therefore, if the user sends a buffer greater than 1504 bytes (including IP and
MAC headers), the packet will be silently dropped.

As another consequence, the commonly used tool `nc` can't be used with Wi-SUN
networks. Indeed, `nc` sends UDP frames of 16kB long. There is no option to
reduce frames size (nor to enable `IPV6_DONTFRAG`).

So, sending UDP packets with `IPV6_DONTFRAG` is recommended. The user may rely
on `IPV6_PATHMTU` and `IPV6_RECVPATHMTU` to know the optimal packet size.

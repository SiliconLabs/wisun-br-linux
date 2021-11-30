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

This projects aims at implementing the Wi-SUN protocol on Linux devices and
allow the use of Linux hosts as Border Router for Wi-SUN networks. For the time
being, the implementation is mostly a port of Silicon Labs embedded stack on a
Linux host. However, the ultimate goal is to replace services currently provided
by the stack by native Linux services.

# Quick Start Guide

## Prerequisites

This project provides the `wsbrd` daemon which is responsible for running the
Wi-SUN protocol high-level layers. It is paired with an RF device RCP (Radio
Co-Processor) handling the low-level layers and RF activities. The RCP devices
currently supported are the EFR32FG12 and EFR32MG12.

The RCP needs to be flashed with a specific firmware in order to communicate
with the daemon. This firmware is provided in binary format. To help users
deploy and evaluate the solution, a [wisun-br-linux-docker][1] repository is
provided. It contains a bundle of all the necessary software components
(including a compiled RCP firmware) to run the Linux Wi-SUN border router.

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
algorithm are enforced.

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

The network interface presented on Linux side is not directly linked to the RF
interface. Instead, `wsbrd` sees the Linux interface as a backhaul and the RF as
a separate interface.

So, you can encounter three interfaces with their own MAC and IPv6 addresses:
  - The Linux interface as displayed by `ip link`
  - The other side of the Linux interface seen by `wsbrd` (called the backhaul
    interface)
  - The RF interface

This is mostly invisible for the end user. However, an attentive user may notice
small details:
  - The DODAGID does not match the IP of the Linux interface
  - The origin of RPL frames does not match the IP of the Linux interface
  - The IPv6 hop-limit (formerly known as TTL in IPv4) field is decremented
  - Direct consequence of the previous item, packet with a hot-limit of 1 are
    not forwarded to the Wi-SUN network. Typically, to ping a multicast address,
    you have to enforce the hop-limit:

    ping -t 2 -I tun0 ff03::fc

  - Multicast link-local frames (typically Router Solicitation and Router
    Advertisement are not forwarded to the Wi-SUN network (these frames are
    ignored in the Wi-SUN network anyway)

## I cannot connect to DBus interface

You have to know there is several DBus instance on your system:
  - One system instance
  - Each user also have a instance

By default, `wsbrd` try to use `user` instance and falls back to `system`
instance.

You can check the DBus session used in the first lines of the log output:

    Successfully registered to system DBus

Then, use `busctl --system` or `busctl --user` accordingly.

Note, that If you use `sudo` to launch `wsbrd` as root user, it will use the
`system` instance.

You can enforce the session used with environment variable
`DBUS_STARTER_BUS_TYPE=system` or `DBUS_STARTER_BUS_TYPE=user`. If you use
`sudo`, you have to define this variable inside the `sudo` environment:

    sudo env DBUS_STARTER_BUS_TYPE=system wsbrd ...


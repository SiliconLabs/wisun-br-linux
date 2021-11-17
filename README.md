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

This project provides a daemon which is responsible of running the Wi-SUN
protocol high-level layers. It is paired with an RF device (Radio Coprocessor,
RCP) handling the low-level layers and RF activities. The RCP devices currently
supported are the EFR32FG12 and EFR32MG12.

The EFR32 needs to be flashed with a specific firmware in order to communicate
with the daemon. This firmware is provided in a binary format. To help users
deploy and evaluate the solution, a repository [wisun-br-linux-docker][1] is
provided. It contains a bundle of all the necessary software components
(including a compiled RCP firmware) to run the Linux Wi-SUN border router.

The communication between the Linux host and the EFR32 is supported through a
serial link (UART). Thanks to the Silicon Labs mainboard, the serial link is
provided over a USB communication. The device `/dev/ACMx` should appears when
you plug the mainboard.

[1]: https://github.com/SiliconLabs/wisun-br-linux-docker

## Compile

The build requires `libnl-3-dev`, `libnl-route-3-dev`, `cmake`. It is also
recommended to have `libsystemd` (note that it can be replaced by `elogind` if
you don't want to pull `systemd`). Optionally, you can also install `libpcap`.

We also encourage the use of Ninja as `cmake` back-end.

On Debian and its derivatives, install the necessary dependencies with:

    sudo apt-get install libnl-3-dev libnl-route-3-dev libpcap-dev libsystemd-dev cmake ninja-build

Then, compile with:

    cmake -G Ninja .
    ninja

And finally, install the service with:

    ninja install

> No script for any start-up service is provided for now.

## Launch

You have to provide a configuration file to the Wi-SUN border router. An
commented example is available in `/usr/local/share/doc/wsbrd/examples/wsbrd.conf`.

    cp -r /usr/local/share/doc/wsbrd/examples .
    <edit examples/wsbrd.conf>

You can copy and edit it. You will notice you need certificates and keys to
authenticate the Wi-SUN nodes of your network. The generation of these files is
described in [[Generate Wi-SUN PKI]].  For now, you can use the certificates
examples installed in `/usr/local/share/doc/wsbrd/examples/`.

You will also need to provide the path of the UART representing your EFR
device.

Finally, you will launch `wsbrd` with:

    sudo wsbrd -F examples/wsbrd.conf -u /dev/ttyACM0

`wsbrd` lists the useful options in the output of `wsbrd --help`.

# Using DBus interface

`wsbrd` provides a DBus interface. You can use a generic DBus tool like
[`busctl`][3] to get communicate with `wsbrd`. Typically, the command below
gives an overview of the DBus interface:

    busctl --user introspect com.silabs.Wisun.BorderRouter /com/silabs/Wisun/BorderRouter

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

# Run `wsbrd` without Root Privileges

It is possible to launch `wsbrd` without root privileges. First, ensure you have
the permission to access the UART device:

    sudo usermod -d dialout YOUR_USER

> You have to logout/login after this step

Create a tun interface:

    sudo ip tuntap add mode tun tun0 user YOUR_USER

Start `wsbrd`:

    wsbrd -F examples/wsbrd.conf -t tun0 -u /dev/ttyACM0

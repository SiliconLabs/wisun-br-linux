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
provided over a USB communication. The device /dev/ACMx should appears when you
plug the mainboard.

[1]: https://github.com/SiliconLabs/wisun-br-linux-docker

## Compile

The build requires `libnl-3-dev`, `libpcap`, and `cmake`. We also encourage the
use of Ninja as `cmake` back-end.

On Debian and its derivatives, install the necessary dependencies with:

    sudo apt-get install libnl-3-dev libpcap-dev cmake ninja-build

Then, compile with:

    cmake -G Ninja .
    ninja

And finally, install the service with:

    ninja install

> No script for any start-up service is provided for now.

## Launch

The Wi-SUN network uses IPv6. Router advertisement on the Wi-SUN network
interface is required to have it function properly.

The configuration of the Router Advertiser highly depends on your network
environment. An example is to run `radvd` with this `radvd.conf`:

    interface tun0
    {
        AdvSendAdvert on;
        IgnoreIfMissing on;
        AdvDefaultLifetime 0;
        prefix fd01:1236::/64
        {
        };
    };

Note that an IPv6 address is also necessary on interface `tun0`. You can provide
one manually with `ip addr add` and leave `radvd` to do the rest with `sysctl
net.ipv6.conf.tun0.accept_ra=2`.

To launch `wsbrd`, a user has to provide the path to the EFR32 device, the
network name and the regulatory domain to use.

In addition, the border router needs certificates and keys to authenticate the
Wi-SUN nodes of the network. The generation of these files is described in
[Generate Wi-SUN PKI](#generate-wi-sun-public-key-infrastructure). You can use the examples installed
under `/usr/local/share/wsbrd/examples/`.

At this point, you should be able to run the Wi-SUN border router daemon with:

    cp -r /usr/local/share/wsbrd/examples/ pki
    sudo wsbrd -n network -d EU -A pki/ca_cert.pem -C pki/br_cert.pem -K pki/br_key.pem -u /dev/ttyACM0

`wsbrd` lists the useful options when calling `wsbrd --help`. A sample
configuration file is installed in `/usr/local/share/wsbrd/examples/wsbrd.conf`.

# Generate Wi-SUN Public Key Infrastructure

The certificate generation process is described in section 6.5.1 of the Wi-SUN
specification. It uses the standard X.509 certificate format. Some fields and
algorithm are enforced.

The process to get official certificates is described on the [Wi-SUN Alliance Web
site][2] (restricted access).

[2]: https://wi-sun.org/cyber-security-certificates/

# Run `wsbrd` without Root Privileges

It is possible to launch `wsbrd` without root privileges. First, ensure you have
the permission to access the UART device:

    sudo usermod -d dialout YOUR_USER

> You have to log out and back in after this step.

Create a tun interface:

    sudo ip tuntap add mode tun tun0 user YOUR_USER

Start `wsbrd`:

    wsbrd -n network -d EU -A pki/ca_cert.pem -C pki/br_cert.pem -K pki/br_key.pem -t tun0 -u /dev/ttyACM0

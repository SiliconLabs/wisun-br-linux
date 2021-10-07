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

The build requires `libnl-3-dev`, `libnl-route-3-dev`, `cmake` and optionally to
`libpcap`. We also encourage the use of Ninja as `cmake` back-end.

On Debian and its derivatives, install the necessary dependencies with:

    sudo apt-get install libnl-3-dev libnl-route-3-dev libpcap-dev cmake ninja-build

Then, compile with:

    cmake -G Ninja .
    ninja

And finally, install the service with:

    ninja install

> No script for any start-up service is provided for now.

## Launch


The Wi-SUN network will use IPv6. Router advertisement on the Wi-SUN network
interface is necessary to make it work correctly.

The configuration of the Router Advertiser highly depends on your network
environment. An example could be to run `radvd` with this `radvd.conf`:

    interface tun0
    {
        AdvSendAdvert on;
        IgnoreIfMissing on;
        AdvDefaultLifetime 0;
        prefix fd01:1236::/64
        {
        };
    };

Note that an IP address will also been necessary on interface `tun0`. You can
provide one manually with `ip addr add` and leave `radvd` to make the job with
`sysctl net.ipv6.conf.tun0.accept_ra=2`.

To launch `wsbrd`, user have to provide the path of the EFR device, the network
name to use and the regulation domain.

Then, you need certificates and keys to authenticate the Wi-SUN nodes of your
network. The generation of these files is described in [[Generate Wi-SUN PKI]].
For now, you can use the examples installed in `/usr/local/share/wsbrd/examples/`.

So, you should be able to run the Wi-SUN Border Router daemon with:

    cp -r /usr/local/share/wsbrd/examples/ pki
    sudo wsbrd -n network -d EU -A pki/ca_cert.pem -C pki/br_cert.pem -K pki/br_key.pem -u /dev/ttyACM0

`wsbrd` lists the useful options in output of `wsbrd --help`. Also note that a
sample configuration file is installed in
/usr/local/share/wsbrd/examples/wsbrd.conf

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

    wsbrd -n network -d EU -A pki/ca_cert.pem -C pki/br_cert.pem -K pki/br_key.pem -t tun0 -u /dev/ttyACM0

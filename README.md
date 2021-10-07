Linux implementation of Wi-SUN
==============================

This projects aims at implementing the Wi-SUN protocol on Linux devices and
allow the use of Linux hosts as Border Router for Wi-SUN networks. For the time
being, the implementation is mostly a port of Silicon Labs embedded stack on a
Linux host. However, the ultimate goal is to replace services currently provided
by the stack by native Linux services.

Quick start guide
-----------------

### Prerequisites

This project provide a daemon which takes care of all the high level stuff of
the Wi-SUN protocol. Then a RF device (RF Co-Processor, RCP) is necessary to
transmit the data. Currently, the only supported device is the Silicon Labs
EFR32.

The EFR32 need to flashed with a specific firmware in order to communicate with
the daemon. The sources of the firmware are not yet publicly available. However,
you can check the repository [wisun-br-linux-docker][1] that contains a bundle
of all the necessary components (including a compiled firmware) to make the
Border Router working.

For now, from the RF device point of view, the serial link is the only bus
supported to communicate with the host. Thanks to the WSTK board, the serial
link is provided over the USB connector of the WSTK board. The device /dev/ACMx
should appears when you plug the WSTK.

[1]: https://github.com/SiliconLabs/wisun-br-linux-docker

### Compile

The project depends on libnl-3-dev, libnl-route-3-dev and optionally to libpcap.
For the build, you will need `cmake`. We also encourage use of Ninja as `cmake`
back-end.

On Debian and its derivatives, you can install the necessary dependencies with:

    sudo apt-get install libnl-3-dev libnl-route-3-dev libpcap-dev cmake ninja-build

Then you can compile with:

    cmake -G Ninja .
    ninja

And finally, you may install the service with:

   ninja install

Note that no scripts for any start-up service are provided for now.

### Launch


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

Generate Wi-SUN PKI
-------------------

The certificate generation process is described in section 6.5.1 of the Wi-SUN
specification. It uses the standard X.509 certificate format. Some fields and
algorithm are enforced.

The process to get official certificates is described on the Wi-SUN alliance web
site[1] (restricted access).

[2]: https://wi-sun.org/cyber-security-certificates/

Run `wsbrd` without root privileges
-----------------------------------

If we are a bit careful, it possible to launch `wsbrd` without root privileges.

First, ensure you have permission to access to UART device:

    sudo usermod -d dialout YOUR_USER

(you have to logout/login after this step)

Create a tun interface:

    sudo ip tuntap add mode tun tun0 user YOUR_USER

Start wsbrd:

    wsbrd -n network -d EU -A pki/ca_cert.pem -C pki/br_cert.pem -K pki/br_key.pem -t tun0 -u /dev/ttyACM0

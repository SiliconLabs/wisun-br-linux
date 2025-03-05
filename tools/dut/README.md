# Device Under Test (DUT) instructions for the Silicon Labs Wi-SUN Linux Border Router

Before starting a test, make sure to delete any information stored from previous
executions:

    sudo wsbrd -DD

The border router should be started with at least 2 configuration files, one
for the base parameters, and one for the PHY parameters. For example:

    sudo wsbrd -F dut.conf -F na/chan-plan-2-dh1cf.conf

More config files can be appended using `-F` depending on the specific test.
Configuration files are provided in [`tools/dut/`](/tools/dut):

  - [`dut.conf`](/tools/dut/dut.conf) contains the base parameters to be
    used with all tests. It should be edited according to the test bed
    configuration.
  - Sub-directories are provided for [North America][na], [Brazil][bz], and
    [Japan][jp]. Each file corresponds to a PHY definition from the Wi-SUN
    Conformance Tests Specification.
  - Some tests expect hard-coded GTKs, add [`sec/gtk.conf`][gtk] to the command
    in that case.

[na]: /tools/dut/na
[bz]: /tools/dut/bz
[jp]: /tools/dut/jp
[gtk]: /tools/dut/sec/gtk.conf

Once the test has run, the border router can be stopped using Ctrl+C.

### IPv6 addresses

The Border Router DUT IPv6 addresses can be retrieved using:

    ip -6 addr show dev tunwsdut

### Multicast ICMPv6

The test `MULTICAST-ORIGINATOR-LBR-1` requires the following operation:

> Step 2: Vendor puts Border Router DUT into a mode where it would transmit a
> multicast ICMPv6 or UDP frame.

This is performed by the following command:

    ping -c 1 -I tunwsdut ff03::1

### GTK Lifecycle

The test `SEC-LIFECYCLE-2` requires the following operations:

A special configuration file [`sec/lifecycle.conf`][lifecycle] is provided to
configure the key lifetimes. It should be added to the command which starts the
border router, for example:

    sudo wsbrd -F dut.conf -F na/chan-plan-2-dh1cf.conf -F sec/lifecycle.conf

[lifecycle]: /tools/dut/sec/lifecycle.conf

### Pairwise Key Revocation

The test `SEC-REVOKE-GTK-1` requires the following operations:

A special configuration file [`sec/revoke.conf`][revoke-cnf] is provided to
configure the key lifetimes. It should be added to the command which starts the
border router, for example:

    sudo wsbrd -F dut.conf -F na/chan-plan-2-dh1cf.conf -F sec/revoke.conf

> Step 1: After all devices have joined, the certificate chain for Test Bed
> Devices I and J is removed from the trusted store of the Authentication
> Server.

The DUT uses an external AAA server so this operation depends on the test bed
configuration.

> Step 8: Border Router DUT revokes the PMK and PTK from Test Bed Device I

> Step 9: Border Router DUT destroys all GTKs except the currently active GTK,
> reduces the lifetime of the currently active GTK and adds a new GTK

A dedicated script [revoke.bash][revoke-sh] is provided to perform these two
steps. It can be run with the MAC address of Device I as argument:

    sudo sec/revoke.bash 00:00:5e:ef:10:00:00:00

> Step 17: Border Router DUT revokes the PMK and PTK from Test Bed Device J

> Step 18: Border Router DUT performs GTK revocation procedure, [...] the
> existing key remains, the next GTK’s lifetime is reduced and a new GTK is
> installed.

The same script is used, using the MAC address of device J:

    sudo sec/revoke.bash 00:00:5e:ef:10:00:00:01

[revoke-cnf]: /tools/dut/sec/revoke.conf
[revoke-sh]:  /tools/dut/sec/revoke.bash

### Powercycle

The test `POWERCYCLE-LBR-1` requires the following operation:

> Step 7: Power the LBR DUT off, wait 2 minutes, and power back up the LBR DUT.

This is achieved by stopping the border router with Ctrl+C, and restarting it
**without** deleting the storage. The full test sequence should look like:

    sudo wsbrd -DD
    sudo wsbrd -F dut.conf -F na/chan-plan-2-dh1cf.conf -F sec/gtk.conf
    ...
    ^C
    sudo wsbrd -F dut.conf -F na/chan-plan-2-dh1cf.conf

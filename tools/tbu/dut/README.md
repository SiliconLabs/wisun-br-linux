# Device Under Test (DUT) instructions for the Silicon Labs Wi-SUN Linux Border Router

Before starting a test, make sure to delete any information stored from previous
executions:

    sudo wsbrd -DD

The border router should be started with 2 configuration files, one for the
base parameters, and one for the PHY parameters. For example:

    sudo wsbrd -F dut.conf -F na/chan-plan-2-dh1cf.conf

Configuration files are provided in [`tools/tbu/dut/`](/tools/tbu/dut):

  - [`dut.conf`](/tools/tbu/dut/dut.conf) contains the base parameters to be
    used with all tests. It should be edited according to the test bed
    configuration.
  - Sub-directories are provided for [North America][na], [Brazil][bz], and
    [Japan][jp]. Each file corresponds to a PHY definition from the Wi-SUN
    Conformance Tests Specification.

[na]: /tools/tbu/dut/na
[bz]: /tools/tbu/dut/bz
[jp]: /tools/tbu/dut/jp

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

[lifecycle]: /tools/tbu/dut/sec/lifecycle.conf

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

A dedicated script [revoke.bash][revoke-sh] is provided, it can be run with
the MAC address of Device I as argument:

    sudo sec/revoke.bash 00:00:5e:ef:10:00:00:00

> Step 9: Border Router DUT destroys all GTKs except the currently active GTK,
> reduces the lifetime of the currently active GTK and adds a new GTK

A dedicated script [revoke.bash][revoke-sh] is provided, it can be run without
any arguments:

    sudo sec/revoke.bash

[revoke-cnf]: /tools/tbu/dut/sec/revoke.conf
[revoke-sh]:  /tools/tbu/dut/sec/revoke.bash

### Powercycle

The test `POWERCYCLE-LBR-1` requires the following operation:

> Step 7: Power the LBR DUT off, wait 2 minutes, and power back up the LBR DUT.

This is achieved by stopping the border router with Ctrl+C, and restarting it
**without** deleting the storage. The full test sequence should look like:

    sudo wsbrd -DD
    sudo wsbrd -F dut.conf -F na/chan-plan-2-dh1cf.conf
    ...
    ^C
    sudo wsbrd -F dut.conf -F na/chan-plan-2-dh1cf.conf

v1.5.3
------

  - PTK and PMK were not properly restored when wsbrd restarted.
  - No longer accept invalid 6LoWPAN fragment packets
  - No longer accept unencrypted data and PAN-config frames

v1.5.2
------

  - Fix handling of channel mask on big endian architectures. Globally all the
    bits arrays has been rewritten to be agnostic with the CPU endianess.

v1.5.1
------

  - PAN-Configuration frames now include LFN Broadcast Interval and LFN
    Broadcast Sync Period. The user can customize these values in the
    configuration file.

v1.5
----

  - Introduce phy_mode_id and chan_plan_id to select a PHY FAN1.1. Also add the
    DBus properties WisunPhyModeId and WisunChanPlanId.
  - We can now advertise FAN1.1 PAN (in the field "FAN TPS Version"). FAN1.1 is
    automatically select if the user uses chan_plan_id. The fan version can
    still be enforced with the fan_version parameter.
  - The advertised FAN version is independent of the chosen PHY. It is possible
    to advertise FAN1.1 protocol with PHY FAN1.0 and vice-versa.
  - Add support for LGTKs (for LFN authentication). The existing API for GTK
    (values, timings, etc...) is also available for LGTKs.
  - Change DBus API to enable "mode switch". It is now possible to set mode
    switch setting for each neighbor.
  - Add needed features to act as TBU for the Wi-SUN certification:
    * Add support for customizable 6LoWPAN MTU
    * Allow to forward received frames to Wireshark
    * Add pan_size parameter to simulate a busy network
    * Fix EUI64 exposed on DBus when an external DHCP is in use
  - Change the file format of the stored data (aka NVM). The new format is human
    readable. Several interesting items can now be easily retrieved (GAK, GTK,
    PMK, PTK, active keys, etc.).
  - By default, the storage folder is no longer readable by other users.
  - Report nodes on the DBus interface as soon as they are authenticated (until
    now, they were reported once registered on RPL tree). The user can check the
    "parent" property to check if the node is registered to the RPL tree.
  - Add a DBus API to subscribe the network to external multicast frames. This
    API is mandated by the Wi-SUN specification. It replaces the MLDv2 (= IGMPv3
    for IPv6) protocol available on classical IPv6 networks.
  - Drop DBus APIs AddRootCertificate and RemoveRootCertificate. We suggest
    relying on external Radius server for production usage.
  - Allow mixing channel plans. We now compare the compatibility of the set of
    RF parameters.
  - Remove 10 sec delay on start.
  - Time was lost when the server restarted.
  - Increase precision of "channel 0 frequency" displayed on start.
  - Remove some useless traces.
  - Fix possible latency when new neighbor is detected with neighbor_proxy
    enabled.
  - Fix PAN config and PAN advert trickles.
  - Fix default permissions of cryptographic material.
  - Fix channel mask usage in asynchronous frames.
  - Add documentation for the DBus API.
  - Mention CPC in the compilation instructions.
  - Simplify timers handling. Also add a trace to track timers usage.
  - Simplify internal DHCP server.

v1.4
----

  - Fix issues related to the internal network interface. This interface has
    been dropped. This implies some changes on the way the interface brings up,
    but they do not impact common user. The only known issue is `ndppd` won't
    works anymore. But the user can replace it by `neighbor_proxy`
  - Improve support for `tun_autoconf = false`. The native IP address is
    properly used has network prefix and as DODAGID.
  - Add support for `neighbor_proxy` parameter. `neighbor_proxy` allows to
    create a transparent bridge between the existing IPv6 network and the Wi-SUN
    network. Wi-SUN network and ethernet network will use the same IPv6 prefix
    and all the hosts will see each other with adding any route on the
    upstream router. This parameter rplace the use of `ndppd`.
  - Fix support for channel plan 2. Channel plan 2 is now automatically
    advertised when the user request FAN1.1 PHY.
  - Drop support for TAP interface (the `use_tap` parameter). It was only
    provided to support ISC-DHCP. Instead we provide patch for ISC-DHCP and
    explanations to work with dnsmasq as an alternative.
  - Drop the internal DHCP relay implementation. The parameter `dhcpv6_server`
    does not exist anymore. The user can now run dhcp_relay beside `wsbrd` (he
    has to use `internal_dhcp=false`).
  - Add support for CPC protocol as an alternative to the traditional UART. The
    CPC protocol bring support for encrypted link and SPI bus.
  - Output is no more colored when redirected. The new parameter `color_output`
    allow to enforce this behavior.
  - Allow to disable storage with `storage_prefix = -`.
  - Fix error catching when certificates are incorrect.
  - Fix default permissions of `/var/lib/wsbrd`
  - Fix paths for examples certificates in examples/wsbrd.conf during the
    install process.
  - Emit a DBus signal when the network topology change.
  - DBus API expose IPv6 of the nodes.
  - Drop `DebugPing` DBus method since there is no more internal IP stack.
  - Introduce wsbrd-fuzz, a developer tool allowing to craft complex scenarios.
    It can also been used to interface with fuzzing tools (ie. American Fuzzing
    Lop).
  - Fix warnings during the build

v1.3.3
------

  - Fix compilation of wsbrd_cli with old Cargo/Rust versions.

v1.3.2
------

  - Fix support for external Radius server
  - Fix simulation tools

v1.3.1
------

  - Fix buffer overflow when mode switch capabilities are advertised.
  - Fix segfault when custom domain is in use.
  - Fix the RF configuration displayed on start up.
  - Slightly change the default lifetimes of MPL and PAN version.

v1.3.0
------

  - Add support for external DHCP server
  - Add support for external Radius server
  - Add support for custom regulation domains
  - allowed_channels now also impact broadcast and asynchronous frames
  - Add support for --list-rf-configs allowing to get the RF configurations
    supported by the RCP. Mainly useful for people who want to use custom RF
    configurations.
  - Display RF configuration and channel masks on start up. So it is now easier
    to setup a custom configuration domain.
  - Catch error from the RCP of the RF configuration is not supported
  - Add support for TAP network interface instead of a TUN network interface
  - Provide wsbrd_cli, a sample client for the DBus interface
  - DBus interface now expose the RPL tree
  - Add alpha support for POM-IE
  - Add alpha support for SetModeSwitch DBus API
  - Improve traces. It is now possible to trace these events: trickles,
    15.4-mngt, 15.4, eap, icmp-rf, icmp-tun, dhcp
  - Disable the non standard algorithm that restrict the Tx windows. The new
    DBus API SetSlotAlgorithm allow to restore previous behavior. Please report
    a bug if you encounter any performance hit with the new default
    configuration.
  - The RF configurations advertised by remotes are now better compared with the
    local RF configuration. So, if a node with with a custom regulatory domain
    try to connect to a BR with a classical domain, they can connect eah other
    if they are compatible.
  - Improve reliability of the UART link. wsbrd is now able to resend corrupted
    frames.
  - Protect UART against concurrent accesses (typically with minicom or another
    wsbrd instance)
  - Increase the range of available UART baudrates
  - wsbrd now relies on Linux for IPv6 fragmentation (while it was done
    internally until now)
  - There is no more default values for "mode" and "class" parameters. They are
    mandatory now
  - Improve interoperability for ARIB
  - Fix excluded channels advertised (unicast and broadcast)
  - Fix case where \x00 was used in configuration file
  - Fix internal timer ticks, wsbrd now wake-up less often
  - Fix some bugs in traces display
  - Provide configuration files for systemd

v1.2.0
------

  - Add a D-Bus API to retrieve list of nodes and their parents. This API can
    be used by third party application to draw diagrams of the network
  - Add automatic subscription to multicast group ff03::
  - Add initial support for region regulations, initially only for ARIB (Japan)
  - Drop built-in MbedTLS; now users must build their own (see README for
    install instructions)
  - Fix missing fields in RCP protocol to support high data rates
  - Allow connection to the RCP even if the OS/HW buffers contain garbage
  - Fix possible overflow on timer IDs
  - Improve simulation tools (developers)


v1.1.0
------

  - Reduce Bufferbloat (https://en.wikipedia.org/wiki/Bufferbloat)
  - Fix possible crash if UART frames are too small to contains CRC
  - Explain some Wi-SUN specificities about frames fragmentation

v1.0.4
------

  - Fix possible dead-lock when wsbrd is started simultaneously with the RCP

v1.0.3
------

  - Fix regression during `ninja install` introduced in v1.0.2

v1.0.2
------

  - Support the way RCP >= 0.5.0 reset. This fix case where node were unable to
    reconnect after wsbrd restarted
  - Fix warning when RCP >= 0.5.0 starts
  - Remove useless --baudrate and --hardflow (it is still possible to use "-o
    uart_baudrate=115200" and "-o uart_rtscts=true"
  - Fix typos in broadcast_interval, broadcast_dwell_interval and
    unicast_dwell_interval
  - Show location when a certificate cannot be read

v1.0.1
------

  - Fix string termination in the configuration file. Especially, the network
    name could be wrong when specified twice
  - Fix a possible deadlock on high workload
  - Fix a possible deadlock when events are canceled
  - Fix support for Chinese PHY
  - Make DBus start more reliable when launched with sudo
  - Fix backtrace display on ARM hosts
  - Improve documentation

v1.0.0
------

  - Fix compatibility with RCP < 0.4.0 (which has a race condition in the UART
    frames reception)
  - Improve case where nodes are ejected from the network (add support for MCPS
    purge)
  - Do not show secrets in logs anymore
  - If available, show backtraces when a bug occurs

v0.4.0
------

  - Allow the filtering of Wi-SUN nodes. Mainly used to build specific network
    topologies
  - Allow retrieving GAKs from DBus interface
  - Add DBus events when GTKs and GAKs are modified
  - Fix build error if libsystemd is not available
  - Also copy documentation during the install process

v0.3.1
------

  - File "CHANGES" has been added in branch v0.2, but not in the main branch.

v0.3.0
------

  - Add DBus interface
  - Allow changing the TX power
  - Allow setting the UART device from a configuration file
  - Allow setting the PAN ID
  - Allow changing parameters relative to GTK lifetime
  - Allow changing dwell delays
  - Fix bug with frames > 1200 bytes
  - Fix error when prefix_storage did not end with '/'
  - Drop references to SPI bus since it is not yet implemented
  - Examples were not copied in the right directory

v0.2.3
------

  - File "CHANGES" was missing

v0.2.2
------

  - Fix creation of /var/lib/wsbrd during install

v0.2.1
------

  - v0.2.0 broke IPv6 routing

v0.2.0
------

  - Do not rely on external Router Advertisements anymore. It is no more
    necessary to launch radvd before wsbrd. wsbrd now relies on `ipv6_prefix`
    parameter.
  - Add parameter "tun_autoconf" to automatically configure the IP of the tun
    interface seen by Linux.
  - Command-line now accepts any parameter accepted in a configuration file
    through "-o KEY=VAL".
  - Fix accepted range for ws_class
  - Change default location of non-volatile data (was /tmp, it is now
    /var/lib/wsbrd)
  - Allow configuring location (and file prefix) of the non-volatile data
  - Allow setting initial GTKs
  - Add a list of valid domain/mode/class combinations in the documentation
  - Fix possible crash on 32bits hosts
  - Remove some traces
  - Provide a better error message if RCP firmware < 0.0.3 replies

v0.1.2
------

  - Fix support for allowed_channel
  - Improve documentation
  - Add a release note

v0.1.1
------

  - Add support for allowed_channel
  - Change the default size of the network (it is "small" now)
  - Do not raise an error if certificates are overloaded from the command line

v0.1
----

  - Fix random seed
  - Increase the number of EAPOL slots

v0.0.7
------

  - Initial pre-alpha release

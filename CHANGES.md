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

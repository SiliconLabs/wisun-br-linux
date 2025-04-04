v2.4
------
  - `wsrd` parenting support:
    * PAN Advertisement frame transmission for children PAN discovery, including
      JM-IE forwarding.
    * EAPoL relay support for children authentication.
    * PAN Configuration frame transmission for children PAN discovery, including
      PAN-wide IE forwarding.
    * RPL DIS reception and DIO transmission for children parent selection.
    * DHCPv6 Relay Agent support for children IPv6 address assignment.
    * Children IPv6 address registration support (NS(ARO)) for downward routing.
    * RPL Packet Information (RPI) hop-by-hop option parsing support for upward
      routing.
    * RPL Source Routing Header (SRH) support for downward routing.
  - Support channel masks during mode switch with `wsbrd`.
  - Fix `wsbrd` duplicate frame detection for EAPoL and LFN unicast frames.
  - Ensure that PAN/LFN version is written to `wsbrd` storage on update and
    only increment by 1 on reboot.
  - Include Auxiliary Security Header in `pcap_file`.
  - Introduce D-Bus methods `RevokeGtks` and `RevokeLgtks` and deprecate
    `RevokeGroupKeys`. These new methods allow to independently revoke GTKs and
    LGTKs as required by the TBU API.
  - Do not stop TBU frame subscription when the border router is stopped.
  - Prevent frame transmissions after TBU is stopped.
  - Fix potential memleak in `wsrd` and `silabs-ws-dc` in case of malformed ACK
    frame reception.

v2.3.2
------
  - Support `EC PRIVATE KEY` format when loading pem files.
  - Prevent `wsrd` and `silabs-ws-dc` from sending unencrypted data frames
    before authentication.
  - Increment PAN/LFN Version on GTK updates with new `wsbrd` authenticator.
  - Increment LFN version on `wsbrd` reboot.
  - Fix outdated LFN Version in `wsbrd` LFN PAN Configuration frames.
  - Fix channel mask for ChanPlanId 4 in Brazil.
  - Fix errors reported by static analyzers.

v2.3.1
------
  - Refresh children IPv6 address registration on reception of inner IPv6
    header with matching source address. Previously only the outer header would
    be analyzed, causing interoperability issues.
  - Accept certificates using the Certificate Policy extension, as used by some
    Wi-SUN intermediate certificates.
  - Increment LFN version on reboot.
  - Improve documentation:
    * Describe `traceroute` limitations.
    * Document common issues with IPv6 forwarding.
    * Improve DUT instructions and add missing configuration files.
    * Add suggestions to [`wisun-borderrouter.service`][service] to help
      integrators.
  - Fix build issues with `endian.h` and `systemd/sd-bus.h`.
  - Fix TBU startup.

[service]: /misc/wisun-borderrouter.service

v2.3
------
  - Update PHY definitions based on Wi-SUN PHY specification 2v03:
    * Realign Singapore PHY definitions with FAN 1.0 (supported ChanPlanIds
      changed from 32,33,38 to 41,42,43).
    * Update Brazil channel masks.
  - Add DHCPv6 Relay Agent implementation to simplify the setup of an external
    DHCPv6 server. See `dhcp_server` in [`wsbrd.conf`][conf].
  - Add `revoke` command to `wsbrd_cli` to force key rotation or invalidation.
  - Add simple GitHub action to compile the project.
  - Support `wsbrd -DD` without providing Wi-SUN parameters.
  - Rename tools for consistency: `wsbrd-fwup` becomes `silabs-fwup` and
    `wshwping` becomes `silabs-hwping`.
  - Rename TBU LFN endpoints according to version 1.1.13.
  - Fix empty JM-IE insersion at boot with TBU.
  - Add CMake rules to build demo programs.
  - New experimental authenticator implementation and integration into `wsbrd`,
    using `AUTH_LEGACY=OFF` in CMake:
    * Increased maintainability compared to the legacy implementation, using a
      straight-forward architecture: ~10k less lines of code, less confusing
      control flow and memory ownership.
    * GTK and LGTK rotation.
    * Internal EAP-TLS implementation.
    * External RADIUS server support.
    * [Key Reinstallation Attack][krack] resilience.
    * [Demo program](/tools/demo/eapol.c) to test and show how the new
      security modules work, including packet loss and key rotation.

[conf]: /examples/wsbrd.conf

v2.2.1
------
  - Fix link-local routing when using IPv6 neighbor proxy.
  - Fix sending 1 too many packets when initiating MPL multicast traffic.
  - Correctly set the `M` bit in MPL packets when initiating traffic.
  - Prevent [Key Reinstallation Attacks][krack] in the `wsrd` supplicant and
    `silabs-ws-dc` authenticator:
    * Refuse to re-install PMK during TLS handshake.
    * Refuse to re-install PTK during 4-way handshake.
    * Refuse to re-install GTK during 4-way and group key handshakes.
    * Correctly increment EAPoL replay counter on authenticator retries.
    * Only reset EAPoL replay counter on PMK installation.
    * Invalidate PTK on PMK installation.
    * Never send a GTK to a supplicant that already knows it based on the GTKL
      KDE.

[krack]: https://www.krackattacks.com/

v2.2
------
  - Add Wi-SUN Linux Router (`wsrd`) demo, functioning as a *leaf node*:
    * Send PAN Advertisement Solicit frames, listen for PAN Advertisements and
      select a PAN.
    * Authenticate and retrieve security keys.
    * Send PAN Configuration Solicit frames, listen for PAN Configurations and
      synchronize to the broadcast schedule.
    * Send DIS packets, listen for RPL DIOs and select a parent using RPL
      metrics.
    * From a global unicast IPv6 address using DHCPv6.
    * Register this address to the primary parent using NS(ARO).
    * Send a DAO to the border router to establish a downard route.
    * Ping and do application traffic to the rest of Wi-SUN and the backhaul.
  - Add Silicon Labs Direct Connect tool (`silabs-ws-dc`) to communicate
    directly with Wi-SUN nodes without routing:
    * Request and establish a pairwaise session with a single node.
    * Authenticate with that node using a provisioned PMK.
    * Ping and do application traffic to that node, even if it is not
      connected to a Wi-SUN network.
  - Update North American OFDM PHY definitions (`phy_mode_id = 0x51-0x54`,
    `chan_plan_id = 4` and `phy_mode_id = 0x34-0x38`, `chan_plan_id = 5`). The
    Wi-SUN PHY specification has undergone a breaking change in version 1vA12.
    Users of the legacy PHY settings are now expected to use `chan0_freq`,
    `chan_spacing` and `chan_count`.
  - Add `pan-defect` command to `wsbrd_cli` to support the [Silicon Labs PAN
    Defect][pan-defect] procedure.
  - Transition `wsbrd` to a new timer system which will help reduce CPU
    consumption with future changes.
  - Force offline compilation of `wsbrd_cli` to avoid network access during
    build. Dependencies must now be retrieved before running CMake, using
    `cargo fetch`.
  - Enable mode switch by default (`phy_operating_modes = auto`) and introduce
    `none` to disable it.
  - Add [`/tools/demo`](tools/demo) files to test individual modules.
  - Fix processing of the EAP identifier.
  - Fix reception of big UART frames.
  - Fix single channel mode.

[pan-defect]: https://docs.silabs.com/wisun/latest/wisun-pan-defect

v2.1.7
------
  - Document the RCP API in [`HIF.md`](HIF.md).
  - Fix IPv6 neighbor proxy: entries referenced the wrong network interface,
    causing Neighbor Advertisement to not be sent.
  - Fix RPL DAO parsing: parents could be assigned to the wrong child when
    multiple transit options are present in the packet.
  - Prevent assert when a neighbor has no known unicast schedule.
  - Prevent invalid memory access in IPv6 neighbor cache.
  - Expose neighbor POM-IE from D-Bus even if mode switch is disabled.
  - Improve trickle configurations for certification tests.

v2.1.6
------
  - Introduce `mac_address` parameter to manually configure the RCP's EUI-64.
  - Accept `chan_plan_id = 160` for Chinese PHY.
  - Fix Segmentation Fault on 6LoWPAN fragmentation failure.
  - Fix memory leak when using `neighbor_proxy`.
  - Fix multicast forwarding under heavy load: MPL buffers used to be kept in
    the network for an unnecessarily long time, causing confusion with packet
    chronology.

v2.1.5
------
  - Improve D-Bus `RoutingGraph`:
    * FFNs neighbors that are not registered through RPL are no longer exposed.
      They would be previously misinterpreted as LFNs during initial connection
      or after expiration.
    * Update signals are no longer emitted for renewed parent registrations
      that do not include any parent change.
  - Support LFN aggregation in RPL DAO packets (consecutive target options for
    one common transit option).
  - Fix use-after-free for multicast packets using MPL.
  - Prevent segfault when using an external RADIUS server.
  - Fix PMK/PTK configuration for LFNs, the FFN value would be used previously.
  - Print backtrace on Segmentation Fault and other crash signals.
  - Fix CPC error code logs.

v2.1.4
------
  - Fix interoperability issue with mode switch: do not include the base
    PhyModeId in advertised POM-IEs.
  - Terminate with a fatal error when a CRC error is detected on the bus:
    missing HIF frames causes complex errors which are usually not recoverable.
  - Use UTC timestamps in `pcap_file` instead of local timebase.

v2.1.3
------
  - Fix `neighbor_proxy`: routing has been broken for nodes more than 1 hop
    away since `v1.7` when using that feature.
  - Improve recovery when a previous neighbor is detected to have moved futher
    away from the border router. Previously, `wsbrd` would keep trying to
    communicate directly with the node until expiration of its address
    registration. Now the neighbor entry is removed when a DAO indicates that
    the border router is no longer a parent.
  - Fix interoperability issue when operating in fixed channel: do not
    advertise any excluded channels.

v2.1.2
------
  - Set the IPv6 hop limit to a fixed value when creating a tunnel, instead of
    copying the received hop limit. Intermediate Wi-SUN hops are now invisible
    to tools like `traceroute`, as it should be for any kind of IP tunnel.
  - Include received acknowledgement frames in `pcap_file`.
  - Change behavior of TBU endpoints `/config/borderRouter/joinMetrics` and
    `/config/borderRouter/informationElements`: previous IEs/metrics are now
    always removed when a new request is received.

v2.1.1
------
  - Fix high CPU usage during intense traffic: packet queues being full caused
    a busy wait in the main loop.
  - Fix `wshwping`:
    * Fix incorrect frame format for parsing RCPv2 ping confirmations.
    * Flush transmission queues on process interruption (`^C` no longer causes
      a freeze at the next program start).
    * Fix invalid and/or missing HIF traces for RCPv2.
  - Fix JM-IE inclusion for TBU:
    * Correctly update the content version number.
    * Include the JM-IE in data frames for when PA transmissions are disabled
      by the trickle algorithm.
    * Insert JM-IE with no metrics instead of it being absent, otherwise
      neighbors do not observe a new content version.

v2.1
------
  - Support separate PTK/PMK lifetimes between FFN and LFN.
  - Remove some authentication limits: more supplicants accepted
    simultaneously, resuling in better authentication delays.
  - Support MPL seed-id omission when operating fully in FAN 1.1 (16 bytes
    saved per multicast packet).
  - MAC mode switch support for TX: D-Bus method `SetModeSwitch` has been
    superseded by `SetLinkModeSwitch`.
  - Support TBU endpoints `/command/borderRouter/rpl/incrementDodagVersion` and
    `/command/borderRouter/rpl/incrementDtsn`.
  - Support experimental EDFE initial frame generation for TBU.
  - Support TBU runtime key insertion in `/config/borderRouter/gtks`.
  - Support runtime MAC filtering via D-Bus methods `AllowMac64` and
    `DenyMac64`, and also TBU endpoint `/config/whitelist`.
  - Fix potential crash at boot on unexpected RCP indication due to race
    condition between RCP reset and reception of a frame on the radio.
  - Fix TBU error handling in `/config/borderRouter/gtks`.
  - Fix `pcap_file` and TBU `/subscription/frames` (RX-only decrypted packet
    capture).

v2.0
------
  - Drop support for legacy RCP API (< 2.0):
    * Neighbor count no longer limited by the RCP memory.
    * Drop `parent` and `ipv6` from the D-Bus `Ǹodes` property,
      developers are now responsible for querying the DHCP server
      in order to map between EUI-64 and IPv6 addresses.
    * `wsbrd_cli` reports the RPL graph using IPv6 addresses (instead of
      EUI-64).
  - Implement Adaptive Power Control (APC) for the Indian regulation (WPC).
  - Prevent LFN desynchronization due to drift over-correction.
  - Fix use-after-free in neighbor handling.
  - Fix some build warnings.
  - `--capture` is now part of the main `wsbrd` executable (no need to
    compile `wsbrd-fuzz`).

v1.9
------
  - Support RCP API version 2.0 (released with GSDK 4.4.1):
    * Multi-rate parameter for transmissions retries.
    * Reduced number of states: timing information and expected frame counters
      are now part of data requests.
    * Automatic detection of RCP API version at boot.
  - Improve reboot behavior:
    * Save and restore RPL routes.
    * Save and restore IPv6 neighbor cache.
    * Introduce D-Bus property `RoutingGraph` and deprecate `ipv6` and `parent`
      fields in `Nodes`.
    * Introduce D-Bus methods to increase RPL counters.
  - Stop forwarding locally scoped multicast packets to LFNs (`ff01::/16` and
    `ff02::/16`).
  - Remove 500 bytes limit to enable mode switch.
  - Improve TBU frame subscription.
  - Internal cleanup.

v1.8.2
------
  - Fix crash on full neighbor table.
  - Fix crash on external RADIUS server unreachable.
  - Fix crash on external RADIUS invalid configuration.
  - Fix replay with `wsbrd-fuzz`.

v1.8.1
------
  - Improve RPL interoperability (accept rank 0)
  - Fix TBU ping for non neighbor nodes
  - Fix TBU PTK lifetime configuration
  - Fix TBU runtime key insertion
  - Support external RADIUS server in `wsbrd-fuzz`

v1.8
------
  - Allow neighbor Limited Function Nodes (LFNs) to subscribe to IPv6 multicast
    groups.
  - Support O-QPSK PHY configurations using PhyModeIds defined by Silicon Labs
    (check `--list-rf-configs`).
  - Update PHY parameters with new standard ChanPlanId definitions.
  - Update FAN 1.0 Indian PHY definitions (`mode = 1a`, `class = 1` and
    `mode = 2a`, `class = 2`). The Wi-SUN PHY specification has undergone a
    breaking change in version 1vA10. Users of the legacy PHY settings are now
    expected to use `chan0_freq`, `chan_spacing` and `chan_count`. Make sure to
    verify that the RCP firmware contains the desired PHY configuration (using
    `--list-rf-configs`).
  - Refresh neighbor IPv6 address registrations on MAC acknowledgements.
  - Support LFN schedule adjusting using LTO-IE for energy optimization.
  - Update Test Bed Unit (TBU) with FAN 1.1 features.
  - Internal cleanup.

v1.7.2
------
  - Fix PAN version advertisement.
  - Prevent multicast loopback for RPL DIO packets.
  - Deprecate `SetSlotAlgorithm` D-Bus method.

v1.7.1
------
  - Fix LFN Time Sync encryption
  - Improve LFN stability
  - Improve key distribution
  - Improve MbedTLS compatibility
  - Fix TBU API `/config/preferredParent`

v1.7
------
  - Updated nodes join ability API (`enable_lfn` and `enable_ffn10` replace
    `fan_version`). FAN 1.0 routers are no longer accepted by default since
    they conflict with LFN support.
  - Fix custom channel mask advertisement (note that Silicon Labs embedded
    Wi-SUN stack older than v1.7.1 becomes incompatible when using that
    feature).
  - Drop support for `wsnode`, `wshwsim` and `wssimserver`, remove some unused
    stack features outside of the scope of a Wi-SUN border router.
  - New simpler RPL root implementation.
  - Test Bed Unit (TBU) API implementation for the Wi-SUN certification.
  - Disable EDFE when regional regulation ARIB is enabled.
  - Fix `--list-rf-configs` for custom PHYs.
  - Fix `wsbrd_cli` compilation using any Rust version >= 1.38

v1.6.4
------

  - Fix MAC address filtering.
  - Fix join metrics IE.
  - Fix `wsbrd-fwup` edge cases.
  - Fix `wsbrd-fuzz` capture from TUN.

v1.6.3
------

  - Fix `wsbrd-fwup` `sx` verification.
  - Documentation complements on LFN D-Bus limitation and IPv6 fragmentation.

v1.6.2
------

  - Revert DBus parameter name declaration to allow for systemd versions older
    than v246.

v1.6.1
------

  - Fix memory leak.
  - DBus interface now declare parameter names.
  - DBus interface now implement `InstallGtk` and `InstallLgtk`.
  - Allow disabling automatic key installation. This feature is used in
    conjunction with `InstallGtk` and `InstallLgtk` for the certification
    process.
  - Cosmetic changes in README.

v1.6
----

  - Allow Limited Function Nodes (LFNs) to connect directly to the Border
    Router. Support for LFN needs FAN1.1 to be enabled (as in release 1.5).
  - The configuration file now accept "lfn_broadcast_interval" and
    "lfn_broadcast_sync_period" parameters.
  - Allow dropping root privileges after startup (see "user" and "group"
    parameters).
  - The new phy_operating_modes parameter allow enabling "PHY mode switch" and
    specifying the list of PHY mode IDs to use. Note that previously "PHY mode
    switch" was enabled opportunistically. To get this behavior, specify
    "phy_operating_modes=auto".
  - phy_operating_modes also allows using "PHY mode switch" with custom
    regulation domains.
  - Don't enable "PHY mode switch" if FAN version is FAN1.0.
  - Value of the POM-IE and the hardware RF configuration index are now
    displayed on startup.
  - "--list-rf-configs" now displays what configurations can be associated in a
    group for phy_mode_switch
  - DBus interface now reports:
    * if the node is authenticated (is_authenticated)
    * if the node is heard by the border router (is_neighbor)
    * the RSSI, if the node is a neighbor (rssi)
    * the RSL measured, if the node is a neighbor (rsl)
    * the RSL advertised by the node, if it is a neighbor (rsl_adv)
    * the node roles (node_role)
    * LGTKs and LGAKs
    * FAN version
  - DBus API RevokeNode has been renamed in RevokePairwiseKeys.
  - DBus API RevokeApply has been renamed in RevokeGroupKeys.
  - wsbrd_cli now reports LGTKs, LGAKs, phy_mode_id, channel_plan_id and FAN
    version.
  - wsbrd_cli now compiles with Rust 2015 (2018 was required before this
    change).
  - New tool "hwping" allows testing a link with the RCP.
  - New tool "fwup" allows upgrading the RCP.
  - Introduce "traces = drop" to traces the reasons the packets are dropped by
    wsbrd. This option may be used to check if remote nodes send malformed
    data. The frames dropped by the RCP are not reported by this interface.
  - All the OFDM MCS (0 to 7) are now accepted in the configuration file.
  - The default tx_power value was too high for most of the devices. The
    default value (14 dBm) is saner.
  - Allow removing the cached data on start with --delete-storage. The previous
    method was to assign "-" to "storage_prefix". It is not longer supported.
  - JM-IE is now reported.
  - Properly report a fatal error if the network name (or any other string
    parameter) is too long.
  - Fix case where the node requests a new GTK. A full 4-way-handshake was
    triggered while 2-way-handshake was sufficient.
  - Fix IPv6 encapsulation when destination is ff03::fc (= all MPL forwarders)
  - Fix display of HIF traces for packet < 9 bytes.
  - Chan plan 1 was automatically used when the user specified a channel
    mask.
  - Warn the user if the chosen PHY is not specified in the chosen regulation
    domain.
  - Since the frame with FSK+FEC modulation can be longer than the constraints
    defined by ARIB, FEC modulations are no longer accepted when ARIB is
    enabled.
  - Clean up output of cmake.
  - Relocate side tools to a subdirectory to make them less visible
  - Mention the tools in README


v1.5.5
------

  - Backport the fix for memory leak introduced in 1.6.1.

v1.5.4
------

  - LFN Broadcast (LBC-IE) was not properly filled.
  - Fix fatal error with rtnl_route_add() when neighbor_proxy was in use.
  - Fix nodes revocation.

v1.5.3
------

  - PTK and PMK were not properly restored when wsbrd restarted.
  - No longer accept invalid 6LoWPAN fragment packets.
  - No longer accept unencrypted data and PAN-config frames.

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

# D-Bus API documentation

`wsbrd` provides a D-Bus API to allow other processes to interact with it. A
generic tool like [`busctl`][3] can be used to communicate. Typically, the
following command gives an overview of the D-Bus interface:

    busctl introspect com.silabs.Wisun.BorderRouter /com/silabs/Wisun/BorderRouter

D-Bus bindings are available in [all][4] [common][5] [languages][6] to build an
application.

[3]: https://www.freedesktop.org/software/systemd/man/busctl.html
[4]: https://www.freedesktop.org/software/systemd/man/sd-bus.html
[5]: https://python-sdbus.readthedocs.io/
[6]: https://www.npmjs.com/package/dbus-next

## Methods

### `SetModeSwitch` (`ayi`)

*Requires RCP API ≥ 2.0.1*

There are two ways to configure mode switch, either global or per neighbor. Each
neighbor can either use the global config, or a node-specific setting.

- `ay`: EUI-64 of a neighbor node on which to configure mode switch, or empty
  array to set the global config
- `i`: one of
  - PHY mode ID (positive value)
  - `0` to use the global mode switch config (only makes sense when an EUI-64
    is specified)
  - `-1` to disable mode switch

Example:

    # Configure global mode switch config with PHY mode ID 84
    SetModeSwitch 0 84

    # Configure neighbor 00:00:5e:ef:10:00:00:00 to use PHY mode ID 85 instead
    # of global config
    SetModeSwitch 8 0x00 0x00 0x5e 0xef 0x10 0x00 0x00 0x00 85

    # Disable mode switch on neighbor 00:00:5e:ef:10:00:00:01
    SetModeSwitch 8 0x00 0x00 0x5e 0xef 0x10 0x00 0x00 0x01 -1

    # Reset neighbor 00:00:5e:ef:10:00:00:00 mode switch to global
    SetModeSwitch 8 0x00 0x00 0x5e 0xef 0x10 0x00 0x00 0x00 0

### `JoinMulticastGroup` and `LeaveMulticastGroup` (`ay`)

In order to send or receive multicast traffic from outside the Wi-SUN network,
this API must be used to join the appropriate multicast group (apart from the
mandatory Wi-SUN multicast group subscriptions `ff02::1`, `ff02::2`, `ff02::1a`,
`ff03::1`, `ff03::2` and `ff03::fc`)

- `ay`: IPv6 multicast address

### `RevokePairwiseKeys` (`ay`)

Remove the Pairwise Transient Key (PTK) and Pairwise Master Key (PMK) associated
with a node as described in the Wi-SUN FAN specification section 6.5.2.5.

- `ay`: 64 bit MAC address of the node to be revoked

### `RevokeGroupKeys` (`ayay`)

Destroy all (L)GTKs except the current active one (and potentially the next
key), reduce the current (or next) key's lifetime, and add a new key, as
described in the Wi-SUN FAN specification section 6.5.2.5.

- `ay`: Explicit key to add as the new GTK (for testing), or 0 length array to
  generate a random key
- `ay`: Idem for LGTKs

### `InstallGtk` and `InstallLgtk` (`ay`)

Install a new explicit (L)GTK in the next available slot. This is only meant for
debug and test. Might be used in conjunction with `(l)gtk_new_install_required =
0` to fully manage the key installation process.

- `ay` 16 bytes long group key

### `IeCustomInsert` (`yyayay`)

Insert a custom Wi-SUN Information Element (IE). There can only be one IE
inserted per type and ID, specifying an existing custom IE will overwrite it,
or remove it if there are no target frames. This is designed for testing but
can also be used to insert vendor IEs (VH-IE or VP-IE for header and payload
respectively). The PAN version will be incremented each time this method is
called. Inserting a custom IE conflicting with a natively inserted IE is not
recommended, as packets will contain two instances of the IE with different
contents.

- `y`: IE type, `0` for Wi-SUN header IE (WH-IE), `1` for nested short Wi-SUN
  payload IE (WP-IE), `2` for nested long WP-IE
- `y`: IE ID (such as `0x06` for VH-IE or `0x03` for VP-IE)
- `ay`: IE content (does not include the IE base nor the sub-ID field for
  WH-IEs)
- `ay`: list of Wi-SUN frame types that the IE should be included in, only a
  subset of frames are supported:

|Frame Type ID| Description         |Abbreviation|
|-------------|---------------------|------------|
|      `0x00` |PAN Advertisement    | PA         |
|      `0x02` |PAN Configuration    | PC         |
|      `0x09` |LFN PAN Advertisement| LPA        |
|      `0x0b` |LFN PAN Configuration| LPC        |

Example:

    # Insert a vendor header IE (VH-IE) in PC frames, using the Silicon Labs
    # Wi-SUN Vendor Identification Number (VIN), and the string "foo" as
    # content. Refer to the Wi-SUN FAN specification for the vendor IE
    # structure.
    IeCustomInsert
      0                         # Type WH-IE
      0x06                      # ID VH-IE
      [26, 'f', 'o', 'o', '\0'] # Silicon Labs VIN followed by "foo"
      [0x02]                    # Insert in PC frames

[1]: https://app.swaggerhub.com/apis/Wi-SUN/TestBedUnitAPI/1.1.4#/default/put_config_borderRouter_informationElements

### `IeCustomClear`

Remove all custom IEs inserted using `IeCustomInsert`, and increment the PAN
version.

### `IncrementRplDtsn`

Increments the RPL Destination Advertisement Trigger Sequence Number (DTSN).
This increment will force all nodes to send a DAO and therefore update all
downward routes of the DODAG. See section 9 of [`RFC 6550`][7] for more details.

### `IncrementRplDodagVersionNumber`

Increments the RPL DODAG Version Number. This increment will form a new version
of the DODAG. See section 8.2.2.1 of [`RFC 6550`][7] for more details.

[7]: https://datatracker.ietf.org/doc/html/rfc6550

## Properties

### `Nodes` (`a(aya{sv})`)

Returns an array of the nodes connected to the Wi-SUN network, with associated
data. Each node is identified by its MAC address, and has a series of properties
provided as key-value pairs. A D-Bus signal is emitted whenever the routing
graph is refreshed.

- `ay`: EUI64
- `a{sv}`: list of properties identified by a string, as described in the
  following table. Not all properties are guaranteed to be present per node
  (ex: a node without parent has no `parent` field)

| Key              |Signature| Comment                                                                  |
|------------------|---------|--------------------------------------------------------------------------|
|`is_border_router`|`b`      |Deprecated. Use `node_role` instead.                                      |
|`node_role`       |`y`      |Semantics from Wi-SUN (`0`: BR, `1`: FFN-FAN1.1, `2`: LFN, none: FFN-FAN1.0)|
|`ipv6`            |`aay`    |Deprecated (Does not survive reboot). Array of IPv6 addresses (usually link-local and GUA)|
|`parent`          |`ay`     |Deprecated (Does not survive reboot). EUI-64 of the preferred parent      |
|`is_authenticated`|`b`      |                                                                          |
|`is_neighbor`     |`b`      |Only nodes that use direct unicast traffic to the border router are listed|
|`rssi`            |`i`      |Received Signal Strength Indication (RSSI) of the last packet received in dBm (neighbor only)|
|`rsl`             |`i`      |Exponentially Weighted Moving Average (EWMA) of the Received Signal Level (RSL) in dBm (neighbor only)|
|`rsl_adv`         |`i`      |EWMA of the RSL in dBm advertised by the node in RSL-IE (neighbor only)   |
|`pom`             |`ay`     |List of PhyModeIds for mode switch advertised in POM-IE (neighbor only)   |
|`mdr_cmd_capable` |`b`      |MAC mode switch support advertised in POM-IE (neighbor only)              |

### `RoutingGraph` (`a(aybaay)`)

Returns an array of the nodes connected to the Wi-SUN network based on routing
information from both RPL and IPv6 neighbor discovery. Each entry in the array
represents a node. A D-Bus signal is emitted whenever the routing graph is
refreshed. Each entry is a structure:

- `ay`: Nodes's IPv6
- `b`: Whether the node an LFN or not.
- `aay`: An array of IPv6 addresses of the node's parents. Entries are sorted
  in the node's preferred order. The border router should be the only entry
  with no parents.

### `Gtks` and `Gaks` (`aay`)

Returns a list of the four Group Transient (or Temporal) Keys (GTKs) or Group
AES Keys (GAKs) used in the network. A signal is emitted upon change. Refer to
the Wi-SUN FAN and IEEE 802.11 specifications for more details.

### `HwAddress` (`ay`)

EUI64 (MAC address) of the RCP

### Wi-SUN configuration

The following properties return the corresponding value set during configuration
(commandline or config file). See `examples/wsbrd.conf` for more details.

| Property name    |Signature| Comment                                          |
|------------------|---------|--------------------------------------------------|
|`WisunNetworkName`|`s`      |                                                  |
|`WisunSize`       |`s`      |                                                  |
|`WisunDomain`     |`s`      |                                                  |
|`WisunMode`       |`u`      |FAN 1.0 mode as hex value (`1a` returns `0x1a` = `26`, `3` returns `0x03` = `3`), or `0` when using FAN 1.1|
|`WisunClass`      |`u`      |FAN 1.0 class, or `0` when using FAN 1.1          |
|`WisunPhyModeId`  |`u`      |FAN 1.1 PHY mode ID, or `0` when using FAN 1.0    |
|`WisunChanPlanId` |`u`      |FAN 1.1 channel plan ID, or `0` when using FAN 1.0|
|`WisunPanId`      |`q`      |                                                  |
|`WisunFanVersion` |`y`      |Semantics from Wi-SUN (`1`: FAN 1.0, `2`: FAN 1.1)|

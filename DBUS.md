# D-Bus API documentation

## Methods

### `SetModeSwitch` (`ayi`)

There are 2 ways to configure mode switch, either global or per neighbor. Each
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

### `SetSlotAlgorithm` (`y`)

The slot algorithm is an experimental feature that tries to avoid collisions
during radio transmission at the expense of additional latency. It is
disabled by default.

- `y`: `0` for disabled, `1` for enabled

## Properties

### `Nodes` (`a(aya{sv})`)

Returns an array of the nodes connected to the Wi-SUN network, with associated
data. Each node is identified by its MAC address, and has a series of
properties provided as key-value pairs. A D-Bus signal is emitted whenenever
the routing graph is refreshed.

- `ay`: EUI64
- `a{sv}`: list of properties identified by a string, as described in the following table:

| Key              |Signature| Comment                                                    |
|------------------|---------|------------------------------------------------------------|
|`is_border_router`|`b`      |                                                            |
|`ipv6`            |`aay`    |Array of IPv6 addresses (usually link-local and GUA)        |
|`parent`          |`ay`     |EUI64 of the preferred parent (only absent if border router)|

### `Gtks` and `Gaks` (`aay`)

Returns a list of the 4 Group Transient (or Temporal) Keys (GTKs) or Group AES
Keys (GAKs) used in the network. A signal is emitted upon change. Refer to the
Wi-SUN FAN and IEEE 802.11 specifications for more details.

### `HwAddress` (`ay`)

EUI64 (MAC address) of the RCP

### Wi-SUN configuration

The following properties return the corresponding value set during
configuration (commandline or config file). See `examples/wsbrd.conf` for
more details.

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

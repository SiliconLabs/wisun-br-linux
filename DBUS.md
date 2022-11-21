# D-Bus API documentation

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

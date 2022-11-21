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

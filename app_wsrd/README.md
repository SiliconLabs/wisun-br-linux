# Wi-SUN Linux Router

Experimental implementation of a Wi-SUN Full Function Node (FFN) for Linux.
Currently only **leaf mode** is supported: `wsrd` cannot serve as a parent
for other nodes. Look and feel should be as close as possible to `wsbrd`, see
[examples/wsrd.conf](examples/wsrd.conf) for available configuration
parameters.

Features:

  - Send PAN Advertisement Solicit frames, listen for PAN Advertisements and
    select a PAN.
  - Authenticate and retrieve security keys.
  - Send PAN Configuration Solicit frames, listen for PAN Configurations and
    synchronize to the broadcast schedule.
  - Send DIS packets, listen for RPL DIOs and select a parent using RPL
    metrics.
  - From a global unicast IPv6 address using DHCPv6.
  - Register this address to the primary parent using NS(ARO).
  - Send a DAO to the border router to establish a downard route.
  - Ping and do application traffic to the rest of Wi-SUN and the backhaul.

Limitations:

  - No MPL support for multicast forwarding.
  - No FFN parenting support (no PA, PC, DIO transmission).
  - No LFN parenting support.
  - No 6LoWPAN fragmentation/reassembly support.

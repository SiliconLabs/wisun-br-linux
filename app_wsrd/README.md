# Wi-SUN Linux Router

Experimental implementation of a Wi-SUN Full Function Node (FFN) for Linux.
Currently only **leaf mode** is supported: `wsrd` cannot serve as a parent
for other nodes. Look and feel should be as close as possible to `wsbrd`, see
[examples/wsrd.conf](/examples/wsrd.conf) for available configuration
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
  - Send PAN Advertisement frames for children PAN discovery, including JM-IE
    forwarding.
  - Encapsulate EAPoL frames into EAPoL Relay packets for children
    authentication.
  - Send PAN Configuration frames for children PAN discovery, including
    PAN/FFN-wide IE forwarding.
  - Process RPL DIS packets and send DIO packets for children parent selection.
  - Encapsulate DHCPv6 packets in DHCPv6 Relay Forward for children IPv6
    address assigment.
  - Process NS(ARO) from children nodes to setup downward routing.
  - Process RPL Packet Information (RPI) hop-by-hop option for upward routing.
  - Process RPL Source Routing Header (SRH) for downward routing.

Limitations:

  - Disconnection procedures are not performed:
    * No DIO poisoning: children are not made aware that connection has been
      lost through wsrd.
    * No NS(ARO) with lifetime 0: parent is not made aware its child is
      leaving. The parent will hold outdated information until timeout.
    * DAO no-path: the border router is not made aware that wsrd has left the
      network. The border router may keep outdated routing information until
      timeout.
  - No reboot support. No data is stored on disk so wsrd needs to perform all
    the initial connection steps again. Frame counters are also not stored so
    neighboring nodes may refuse wsrd frames after the 2nd connection.
  - No MPL support for multicast forwarding.
  - No LFN parenting support.
  - No 6LoWPAN fragmentation/reassembly support.

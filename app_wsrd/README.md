# Wi-SUN Linux Router

Experimental implementation of a Wi-SUN Full Function Node (FFN) for Linux.
Look and feel should be as close as possible to `wsbrd`, see
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
  - Store important data on disk and restore on restart to accelerate
    reconnection: security keys, frame counters, PAN ID...
  - Perform DIO poisoning to inform children when `wsrd` is no longer able to
    parent.
  - Send NS(ARO) with lifetime 0 to the parent before leaving the network.
  - Send DAO No-Path to the border router to inform that `wsrd` is purposely
    leaving the network.
  - Respond to NA(EARO) for Registration Refresh Request to accelerate parent
    recovery.

Limitations:

  - No secondary parent selection and registration.
  - No RPL hop-by-hop option inserted in IPv6 packet: no IPv6-in-IPv6 tunnel is
    created and no loop detection is possible for local repair.
  - No filtering of RPL candidates based on the RSL.
  - No handling of RPL DODAG Version Number and DTSN normally used to
    accelerate global network recovery.
  - No MPL support for multicast forwarding.
  - No LFN parenting support.
  - No 6LoWPAN fragmentation/reassembly support.
  - No mode switch transmission and advertisement support.

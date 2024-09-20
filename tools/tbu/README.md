# Wi-SUN Test Bed Unit for Silicon Labs border router

This project implements the [Wi-SUN TBU REST API][1] for [`wsbrd`][1].

[1]: https://app.swaggerhub.com/apis/Wi-SUN/TestBedUnitAPI/1.0.18
[2]: https://github.com/SiliconLabs/wisun-br-linux

## Setup

[`Dnsmasq`][3] is used as a DHCPv6 relay. The version used must be at least
`v2.87`. Compiling from source may be required for distributions providing an
older version through their package manager.

    sudo apt install dnsmasq

The server needs to be run as root, so the Python dependencies must be
installed for the root user:

    sudo pip3 install -r requirements.txt

A couple `systemd` services need to be installed:

    sudo install -m 0644 systemd/wisun-borderrouter.service /etc/systemd/system
    sudo install -m 0644 systemd/wstbu-dhcpv6-relay.service /usr/local/lib/systemd/system
    sudo install -m 0755 systemd/wstbu-dhcpv6-relay         /usr/local/bin
    sudo systemctl daemon-reload

The TBU server is configured using a configuration file. An example given in
[`config.ini`](config.ini).

Finally, the server can be run using:

    sudo python3 wstbu.py config.ini

[3]: https://thekelleys.org.uk/dnsmasq/doc.html

## Known limitations

- Only a single instance of this TBU can run on a given host.
- Most configuration endpoints can only be used before starting the border
  using `/runMode/1`.
- The frame subscription feature enabled with `/subscription/frames` does not
  include acknowledgement frames, and does not include the auxiliary security
  header.
- Channel exclusions set using `/config/chanPlan/unicast` or
  `/config/chanPlan/bcast` do not respect the format used (range or mask), the
  border router chooses the format that takes the least bytes to express the
  channel exclusions. Moreover the border router does not support having
  different channel exclusions between its unicast and broadcast schedules, so
  the last exclusion set using one of the 2 endpoints will be used for both
  unicast and broadcast.
- Broadcast Schedule Identifier (BSI) is ignored in `/config/chanPlan/bcast`,
  a random BSI is generated instead.
- Endpoints `/config/neighborTable` and `subscription/frames/hash` are not
  implemented.
- Endpoint `/config/borderRouter/revokeKeys` will always revoke both GTKs and
  LGTKs, inserting a custom (L)GTK based on the `isLgtk` parameter, and a
  random key for the other key type.

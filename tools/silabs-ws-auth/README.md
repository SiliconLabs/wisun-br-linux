# Wi-SUN Authenticator for Key Sharing between PANs

This project extracts the authenticator part of the Border Router in order to
allow centralizing key distribution accross several PANs. When configured to
use a remote external authenticator, `wsbrd` will forward EAPoL packets and
also fetch keys for its own usage.

The MQTT protocol is used to distribute keys to the border routers. This
implementation has been developped and tested using [Mosquitto][mosq]. `wsbrd`
instances subscribe to the `gtks` topic, and `silabs-ws-auth` publishes GTK
values along with some metadata.

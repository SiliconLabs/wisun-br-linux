#!/bin/bash -e

echo "Revoke PMK/PTK for $EUI64"
IFS=':-' read -r -a EUI64 <<< "$EUI64"
busctl call --timeout=1 \
    com.silabs.Wisun.BorderRouter \
    /com/silabs/Wisun/BorderRouter \
    com.silabs.Wisun.BorderRouter \
    RevokePairwiseKeys ay ${#EUI64[@]} $(for b in "${EUI64[@]}"; do echo "0x$b"; done)

echo "Revoke GTK/LGTK"
busctl call --timeout=1 \
    com.silabs.Wisun.BorderRouter \
    /com/silabs/Wisun/BorderRouter \
    com.silabs.Wisun.BorderRouter \
    RevokeGroupKeys ayay 0 0

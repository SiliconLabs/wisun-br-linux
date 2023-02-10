RCP Hardware Interface
======================

This document describes the Hardware InterFace (HIF). HIF is the API between
`wsbrd` and the RCP device.

General observations
--------------------

In this specification, the prefix used in the command means:
  - `REQ` (request): a command send from the host to the device
  - `CNF` (confirmation): a reply from the device to the host
  - `IND` (indication): a spontaneous frame from the device to the host

All the types used are little endian.

The type `bool` is a `uint8_t`, but only the LSB is interpreted. All the other
bits are reserved.

When a bit is reserved or unassigned, it be set to 0 by the transmitter and must
be ignored by the receiver.

All the version numbers are encoded using `uint32_t` with the following mask:
  - `0xFF000000` Major revision
  - `0x00FFFF00` Minor revision
  - `0x000000FF` Patch

Frame structure
---------------

The RCP can use the _Native UART_ or the _CPC_ protocol. With CPC, the frame
structure is defined by the CPC specification.

With Native UART, the frame structure is:

 - `uint16_t len`  
    Length of the payload (= `cmd` + `body` + `fcs`). Only the 11 least
    significant bits (`0x7FF`) are used. The 5 most significant bits (`0xF800`)
    must ignored.

 - `uint16_t hcs`  
    CRC16 of the `len` field.

 - `uint16_t cmd`  
    Command number. For now only the 8 least significant bits are used.

 - `uint8_t body[]`  
    Command body.

 - `uint16_t fcs`  
    CRC16 of (`cmd` + `body`) fields.

Administrative commands
-----------------------

### `0x01 REQ_NOP`

No-operation. Can be used to synchronize UART communication.

 - `uint8_t garbage[]`  
    Data after command is ignored.

### `0x02 IND_NOP`

No-operation. Can be used to synchronize UART communication.

 - `uint8_t garbage[]`  
    Extra data may be included. Must be ignored.

### `0x03 REQ_RESET`

Hard reset the RCP. After this command, the host will receive `IND_RESET`.

 - `bool enter_bootloader`  
    If set, start the bootloader instead of normal firmware. Set this field if
    you want to flash a new firmware. Refer to the bootloader documentation to
    know how to send the new firmware (usually, the XMODEM protocol is used to
    send the new firmware other the UART).

### `0x04 IND_RESET`

Sent on boot of the RCP. This command may be caused by a power on, `REQ_RESET`,
a debugger, etc...

 - `uint32_t api_version`  
    Device API version

 - `uint32_t fw_version`  
    Device version

 - `char fw_version_str[]`  
    Device version string. It may include version annotation (ie.
    `1.5.0-5-ga91c352~bpo`).

 - `uint8_t hw_eui64[8]`  
    EUI64 flashed in the device

 - `uint8_t reserved[]`  
    Extra data may be included. For backward compatibility, they must be
    ignored.

### `0x05 IND_FATAL`

Commands don't reply in case of success. If the device gets misconfigured or if
any other fatal error happens, the device will reset. In this case, `IND_FATAL`
may be sent before `IND_RESET`. It contains information about the error. It can
be used display the error to the user of for debugging purpose.

 - `uint8_t error_code`  
    Known error codes:
     - `0x01`: unsupported host API (`REQ_HOST_API`)
     - `0x02`: unsupported radio configuration (`REQ_SET_RADIO_CONFIG`)
     - `0x03`: radio not configured (`REQ_ENABLE_RADIO`)
     - `0x04`: enable to allocate entry (`REQ_SET_FRAME_COUNTER_RX`)
     - `0x05`: enable to allocate entry (`REQ_SET_SRC16_FILTER`)
     - `0x06`: enable to allocate entry (`REQ_SET_SRC64_FILTER`)
     - `0xFF`: unexpected assert

 - `char error_string[]`  
    Human readable error.

### `0x06 REQ_HOST_API`

Inform RCP about the host API version. If not send, the RCP will assume `2.0.0`.
This command should be sent after `IND_RESET`, before any other command.

 - `uint32_t api_version`  
    Must be at least `0x02000000`.

Send and receive data
---------------------

### `0x10 REQ_TX`

 - `uint8_t id`  
    An arbitrary ID send back in `CNF_TX`. Also used in `REQ_DROP_FRAME`.

 - `uint16_t payload_len`  
    Length of the next field

 - `uint8_t payload[]`  
    A well formed 15.4 frame (at least, it must start with a valid 15.4 header).
    The device will retrieve the destination address, the auxiliary security
    header and other 15.4 properties from this field.

    In addition, if the following fields are present, they are automatically
    updated by the device:
      - Sequence number
      - "Unicast Fractional Sequence Interval" in the UTT-IE
      - "Broadcast Slot Number" in the BT-IE
      - "Broadcast Interval Offset" in the BT-IE
      - "Unicast Slot Number" in the LUTT-IE
      - "Unicast Interval Offset" in the LUTT-IE
      - "LFN Broadcast Slot Number" in the LBT-IE
      - "LFN Broadcast Interval Offset" in the LBT-IE
      - If the auxiliary security header is present, the device will encrypt the
        15.4 payload (see `REQ_SET_KEY`) and fill the MIC and the frame
        counter

 - `uint16_t flags`  
    A bitfield:
     - `0x0007 FHSS_TYPE_MASK`: Type of frequency hopping algorithm to use:
         - `0x00 FHSS_TYPE_FFN_UC`
         - `0x01 FHSS_TYPE_FFN_BC`
         - `0x02 FHSS_TYPE_LFN_UC`
         - `0x03 FHSS_TYPE_LFN_BC`
         - `0x04 FHSS_TYPE_ASYNC`
         - `0x06 FHSS_TYPE_LFN_PA`
     - `0x0008 RESERVED`: Possible extension of `FHSS_TYPE_MASK`
     - `0x0030 FHSS_CHAN_FUNC_MASK`:
         - `0x00 FHSS_CHAN_FUNC_FIXED`
         - `0x01 FHSS_CHAN_FUNC_TR51`
         - `0x02 FHSS_CHAN_FUNC_DH1`
         - `0x03 FHSS_CHAN_FUNC_AUTO`: Use value specified in `PROP_CONF_FHSS`.
           The exactly meaning depend of `FHSS_TYPE_MASK`
     - `0x0040 RESERVED`: Possible extension of `FHSS_CHAN_FUNC_MASK`
     - `0x0080 EDFE`
     - `0x0100 USE_MODE_SWITCH`
     - `0x0600 RESERVED`: For priority

Only present if `FHSS_TYPE_FFN_UC`:

 - `uint64_t rx_timestamp_mac_us`  
    Timestamp (relative to the date of the RCP reset) of the last received
    message for this node. The host will use the `timestamp_mac_us` value from
    commands `CNF_TX` and `IND_RX`.  
    FIXME: Is uint32_t in milliseconds would be sufficient? Should we spend 4
    extra bytes for this data?

 - `uint24_t ufsi`  

 - `uint8_t dwell_interval`  

 - `uint8_t clock_drift`  
    (unused)

 - `uint8_t timing accuracy`  
    (unused)

Only present if `FHSS_TYPE_LFN_UC`:

 - `uint64_t rx_timestamp_mac_ms`  
    Timestamp (relative to the date of the RCP reset) of the last received
    message for this node. The relevant information can found in the field
    `timestamp_mac_us` of commands `CNF_TX` and `IND_RX`.  
    FIXME: Is uint32_t in milliseconds would be sufficient? Should we spend 4
    extra bytes for this data?

 - `uint16_t slot_number`  

 - `uint24_t interval_offset_ms`  

 - `uint24_t interval_ms`  

 - `uint8_t  clock_drift`  
    (unused)

 - `uint8_t  timing accuracy`  
    (unused)

Only present if `FHSS_TYPE_FFN_BC`: (TBD)

 - `uint16_t slot_number`  

 - `uint32_t interval_offset_ms`  

Only present if `FHSS_TYPE_LFN_BC`: (TBD)

 - `uint16_t slot_number`  

 - `uint24_t interval_offset_ms`  

Only present if `FHSS_TYPE_LFN_PA`:

 - `uint16_t first_slot`  

 - `uint8_t  slot_time_ms`  

 - `uint8_t  slot_count`  

 - `uint24_t response_delay_ms`  

Only present if `FHSS_TYPE_ASYNC`:

 - `uint16_t max_tx_duration_ms`  

Only present if `FHSS_CHAN_FUNC_FIXED`:

 - `uint16_t chan_nr`  
    Fixed channel value.

Only present if `FHSS_CHAN_FUNC_DH1`:

 - `uint8_t chan_mask_len`  
    Length of the next field. Maximum value is 64.

 - `uint8_t chan_mask[]`  
    Bitmap of masked channels.

Only present if `FHSS_CHAN_FUNC_TR51`:

 TBD

Only present if `USE_MODE_SWITCH`:

 - `uint8_t phy_modes[2][4]`  
    An array of `phy_mode_id` and number of attempt to do for each of them.

### `0x11 REQ_DROP_FRAME`

 - `uint16_t id`  
    `id` provided in `REQ_TX`

### `0x12 CNF_TX`

Status of the earlier `REQ_TX`.

This API contains several timestamps. Instead encoding absolute timestamps, it
provide difference with the last step. Thus the message is shorter.

 - `uint8_t id`  
    `id` provided in `REQ_TX`

 - `uint8_t status`  
    Fine if 0. The fields below may be invalid if `status != 0`

 - `uint16_t payload_len`  
    Length of the next field (can be 0 if `status != 0`). Maximum value is 2047.

 - `uint8_t payload[]`  
    15.4 ack frame. Can contains data if EDFE is enabled.

 - `uint64_t timestamp_mac_us`  
    The timestamp (relative to the date of the RCP reset) when the frame have
    been received on the device.

 - `uint32_t delay_mac_buffers_us`  
    Duration the frame spend in the MAC buffer before to access to the RF
    hardware. `timestamp_mac_us + delay_mac_buffer_us` give the timestamp
    of the beginning of the first tentative to send the frame.

 - `uint32_t delay_rf_us`  
    Duration the frame spend in the RF hardware before to successfully send the
    frame. `timestamp_mac_us + delay_mac_buffer_us + delay_rf_us` give
    the time when the frame has started to be sent.  

 - `uint16_t duration_tx_us`  
    Effective duration of the frame on the air. `timestamp_mac_us +
    delay_mac_buffer_us + delay_rf_us + duration_tx` gives the timestamp of
    the end of the tx transmission.  

 - `uint16_t delay_ack_us`  
    Delay between end of frame transmission and the start of ack frame.
    `tx_timestamp_mac_us + delay_mac_buffer_us + delay_rf_us +
    duration_tx + delay_ack_us` give the timestamp of the reception of the ack
    (aka `rx_timestamp_us`).  

 - `uint8_t  rx_lqi`  

 - `int16_t  rx_signal_strength_dbm`  
    More or less the same than RSSI.  

 - `uint32_t tx_frame_counter`  

 - `uint16_t tx_channel`  
    The effective channel used.  

 - `uint8_t tx_count1`  
    Number of transmissions including retries due to CCA.  
    If `status == 0`, `tx_count1` is at least 1.

 - `uint8_t tx_count2`  
    Number of transmission without counting failed CCA. `tx_count1` is always `>=
    tx_count2`.  
    If `status == 0`, `tx_count2` is at least 1.

 - `uint8_t flags`  
    A bitfield:
    - `0x01: HAVE_MODE_SWITCH_STAT`

Only present if `HAVE_MODE_SWITCH_STAT`:

 - `uint8_t phy_modes[4]`
    Number time each `phy_mode` has been used. Sum of these fields is equal to
    `tx_count2`.

### `0x13 IND_RX`

 - `uint16_t payload_len`  
    Length of the next field. Maximum value is 2047.

 - `uint8_t payload[]`  
    15.4 frame.

 - `uint64_t timestamp_rx_us`  
    The timestamp (relative to the date of the RCP reset) when the frame have
    been received on the device.

 - `uint16_t duration_rx_us`  
    Effective duration of the frame on the air. `timestamp_rx_us +
    duration_rx` gives the timestamp of the end of the rx transmission.

 - `uint8_t rx_lqi`  

 - `int16_t rx_signal_strength_dbm`  

 - `uint8_t rx_phymode_id`  
    The effective phy used.

 - `uint16_t rx_channel`  
    The effective channel used.

 - `uint16_t filter_flags`  
    Same bit field than `PROP_FILTERS`  
    If one bit is set, the frame should had been filtered but the filter is not
    enabled.

 - `uint8_t flags`  
    Reserved for future usage.

Radio configuration
-------------------

### `0x20 REQ_ENABLE_RADIO`

Start (or stop) receiving radio data. `REQ_SET_RADIO_CONFIG`,
`REQ_SET_CONF_FHSS_UC` (and probably several others) must have been called
before this function.

 - `bool value`  
    Only `true` is implemented

### `0x21 REQ_LIST_RADIO_CONFIG`

Get the list of radio configuration supported by the device.

Body of this command is empty.

### `0x22 CNF_LIST_RADIO_CONFIG`

 - `bool list_end`  
    If not set, the list will continue in another `CNF_LIST_RADIO_CONFIG`.

 - `uint8_t len`  
    Number of entries in next field.

 - `struct rf_config[]`  
    - `uint16_t flags`
        - `0x0001`: If set, this entry is in same group than the previous.
        - `0xFFF0`: Supported MCSs (from MCS0 to MCS11)
    - `uint8_t rail_phy_mode_id`: Same than phy_mode_id, but for OFDM, only MCS0
      is retrieved.
    - `uint32_t chan_base_khz`
    - `uint32_t chan_spacing_hz`
    - `uint16_t chan_count`

### `0x23 REQ_SET_RADIO_CONFIG`

Configure the radio parameters.

 - `uint8_t index`  
    Index in the `rf_config` list

 - `uint8_t mcs`  
    MCS to be used if `index` points to an OFDM modulation

### `0x24 REQ_SET_REGIONAL_REGULATION`

Allow to enable specific RF regulation rules. Most of the regulations only make
sense with a specific channel configuration.

 - `uint32_t value`  
    - `0`: None
    - `1`: North America (FCC)
    - `2`: Japan (ARIB)
    - `3`: Europe (ETSI)

### `0x25 REQ_SET_TX_POWER`

FIXME: define unit

FIXME: define default value

 - `int32_t value`  

Frequency Hopping (FHSS) configuration
--------------------------------------

### `0x30 REQ_SET_CONF_FHSS_UC`

 - `uint16_t flags`  
    A bitfield
    :
     - `0x0030: FHSS_CHAN_FUNC_MASK`:
        - `0: FHSS_CHAN_FUNC_FIXED`: Use Fixed Channel
        - `1: FHSS_CHAN_FUNC_TR51`: Use TR51
        - `2: FHSS_CHAN_FUNC_DH1`: Use DH1
        - `3: RESERVED`: (`FHSS_CHAN_FUNC_AUTO`)

Only present if `FHSS_CHAN_FUNC_FIXED`:

 - `uint16_t chan_nr`  
    Fixed channel value.

Only present if `FHSS_CHAN_FUNC_DH1`:

 - `uint8_t chan_mask_len`  
    Length of the next field. Maximum value is 64.

 - `uint8_t chan_mask[]`  
    Bitmap of masked channels.

Only present if `FHSS_CHAN_FUNC_TR51`:

  TBD

Always present:

 - `uint16_t uc_dwell_interval_ms`  
    Note this only impact the Rx scheduling. The `dwell_interval` of the
    destination is specified in `PROP_FRAME`.

 - `uint8_t hop_rank`  
    Rank number in the RPL tree. If unknown, 0 is fine (FIXME: fact check that).

 - `bool disallow_tx_on_rx_slots`  
    TBD.

### `0x31 REQ_SET_CONF_FHSS_FFN_BC`

 - `uint16_t flags`  
    A bitfield:
     - `0x0030: FHSS_CHAN_FUNC_MASK`:
        - `0: FHSS_CHAN_FUNC_FIXED`: Use Fixed Channel
        - `1: FHSS_CHAN_FUNC_TR51`: Use TR51
        - `2: FHSS_CHAN_FUNC_DH1`: Use DH1
        - `3: RESERVED`: (`FHSS_CHAN_FUNC_AUTO`)

Only present if `FHSS_CHAN_FUNC_FIXED`:

 - `uint16_t chan_nr`  
    Fixed channel value.

Only present if `FHSS_CHAN_FUNC_DH1`:

 - `uint8_t chan_mask_len`  
    Length of the next field. Maximum value is 64.

 - `uint8_t chan_mask[]`  
    Bitmap of masked channels.

Only present if `FHSS_CHAN_FUNC_TR51`:

  TBD

Always present:

 - `uint16_t ffn_bc_broadcast_schedule_id`  

 - `uint32_t ffn_bc_interval_ms`  

 - `uint16_t ffn_bc_dwell_interval`  

 - `uint8_t ffn_bc_clock_drift`  
    (unused)

 - `uint8_t ffn_bc_timing accuracy`  
    (unused)

### `0x32 REQ_SET_CONF_FHSS_LFN_BC`

 - `uint16_t flags`  
    A bitfield:
     - `0x0030: FHSS_CHAN_FUNC_MASK`:
        - `0: FHSS_CHAN_FUNC_FIXED`: Use Fixed Channel
        - `1: FHSS_CHAN_FUNC_TR51`: Use TR51
        - `2: FHSS_CHAN_FUNC_DH1`: Use DH1
        - `3: RESERVED`: (FHSS_CHAN_FUNC_AUTO)

Only present if `FHSS_CHAN_FUNC_FIXED`:

 - `uint16_t chan_nr`
    Fixed channel value.

Only present if `FHSS_CHAN_FUNC_DH1`:

 - `uint8_t chan_mask_len`  
    Length of the next field. Maximum value is 64.

 - `uint8_t chan_mask[]`  
    Bitmap of masked channels.

Only present if `FHSS_CHAN_FUNC_TR51`:

  TBD

Always present:

 - `uint32_t lfn_bc_interval_ms`  

 - `uint16_t lfn_bc_broadcast_schedule_id`  

 - `uint8_t lfn_bc_sync_period`  

### `0x33 REQ_SET_CONF_FHSS_ASYNC`

 - `uint16_t flags`  
    A bitfield:
     - `0x0030: FHSS_CHAN_FUNC_MASK`:
        - `0: FHSS_CHAN_FUNC_FIXED`: Use Fixed Channel
        - `1: FHSS_CHAN_FUNC_TR51`: Use TR51
        - `2: FHSS_CHAN_FUNC_DH1`: Use DH1
        - `3: RESERVED`: (`FHSS_CHAN_FUNC_AUTO`)

Only present if `FHSS_CHAN_FUNC_FIXED`:

 - `uint16_t chan_nr`  
    Fixed channel value.

Only present if `FHSS_CHAN_FUNC_DH1`:

 - `uint8_t chan_mask_len`  
    Length of the next field. Maximum value is 64.

 - `uint8_t chan_mask[]`  
    Bitmap of masked channels.

Only present if `FHSS_CHAN_FUNC_TR51`:

  TBD

Security
--------

### `0x40 REQ_SET_KEY`

 - `uint8_t slot`  
    Key slot to assign. The Wi-SUN RCP have 8 slots.

 - `uint8_t key[16]`  
    Key payload. If `key == 0`, the slot is disabled.

 - `uint32_t frame_counter`  
    The initial frame counter value (for transmission). Can be changed later
    with `REQ_SET_FRAME_COUNTER_TX`.

 - `uint8_t flags`  
    A bitfield:
     - `0x0003: KEY_IDENTIFY_MODE_MASK`:
        - `0: KEY_IDENTIFY_MODE_IMPLICIT`: Not supported
        - `1: KEY_IDENTIFY_MODE_INDEX`: Use `key_index`
        - `2: KEY_IDENTIFY_MODE_SRC4`: Not supported
        - `3: KEY_IDENTIFY_MODE_SRC8`: Not supported

Only present if KEY_IDENTIFY_MODE_INDEX:

 - `uint8_t key_index`  
    The `Key Index` to match in the auxiliary security header.

### `0x41 REQ_SET_FRAME_COUNTER_TX`

 - `uint8_t slot`  
    Key slot to assign.

 - `uint32_t value`  
    New frame counter value.

FIXME: This API is useless for now.

### `0x42 REQ_SET_FRAME_COUNTER_RX`

 - `uint16_t panid`  
 - `uint16_t addr16`  
 - `uint8_t addr64[8]`  
 - `uint8_t key_id`  
    These for fields are used to match the right key.

 - `uint32_t value`  
    Frame counter value to set. If `value == 0xFFFFFFFF`, the entry is dropped.
    If the RCP is not able to allocate the memory for the internal neighbor
    table entry, it will send a `IND_FATAL` and reset.

FIXME: should we add a field in `IND_RESET` to have the number of entry in the
neighbor table?

Filtering
---------

### `0x50 REQ_SET_FILTERS`

Ask the device to discard certain frames to the host. By default, all the
filters are enabled.

 - `uint16_t value`  
    A bitfield:
     - `0x0001 FILTER_BAD_FCS` (forward encrypted frame if not set)
     - `0x0002 FILTER_BAD_RSSI` (forward encrypted frame if not set)
     - `0x0004 FILTER_BAD_HEADER` (forward encrypted frame if not set)
     - `0x0008 FILTER_BAD_KEY` (forward encrypted frame if not set)
     - `0x0010 FILTER_BAD_MIC`
     - `0x0020 FILTER_BAD_FRAME_COUNTER`
     - `0x0040 FILTER_BAD_PANID`
     - `0x0080 FILTER_BAD_DEST`
     - `0x0100 FILTER_BAD_SRC64`
     - `0x0200 FILTER_BAD_SRC16`
     - `0x1000 FILTER_NOT_DATA_FRAME_TYPE` (mainly received Ack)
     - `0x2000 FILTER_RCP_GENERATED` (mainly transmitted Ack)

### `0x58 REQ_FILTER_MIN_RSSI`

If `FILTER_BAD_RSSI` is set, drop frames with RSSI inferior to this value.

FIXME: define default value

FIXME: define units

 - `int32_t value`  

### `0x59 REQ_FILTER_DST64`

If `FILTER_BAD_DEST` is set, drop unicast frames which destination is not this
address. By default, it use the EUI64 returned in `IND_RESET`.

 - `uint8_t value[8]`  

### `0x5A REQ_FILTER_DST16`

If `FILTER_BAD_DEST` is set, drop unicast frames which destination is not this
address. Default value of `0xFFFF` (all frame with using short address are
discarded).

 - `uint16_t value`  

### `0x5B REQ_FILTER_PANID`

If `FILTER_BAD_PANID` is set, drop frames which destination is not this PAN ID.

FIXME: define default value

 - `uint16_t value`  

### `0x5C REQ_FILTER_SRC64`

If `FILTER_BAD_SRC64` is set, drop frames coming from denied extended addresses.

 - `bool allowed_list`  
   Instead of setting a list of denied address, set a list of allowed addresses

 - `uint8_t entry_count`  
   Number of entries in the next field

 - `uint8_t addr64[8][]`  
   Addresses to deny/allow.

By default, the denied list is empty.

If the RCP is not able to allocate the memory for the filter table, it will send
a IND_FATAL and reset.

FIXME: should we add a field in IND_RESET to have the number of entry in the
filter table?

### `0x5D REQ_FILTER_SRC16`

If `FILTER_BAD_SRC16` is set, drop frames coming from denied short addresses.

 - `bool allowed_list`  
   Instead of setting a list of denied address, set a list of allowed addresses

 - `uint8_t entry_count`  
   Number of entries in the next field

 - `uint16_t addr16[]`  
   Addresses to deny/allow.

By default, the denied list is empty.

If the RCP is not able to allocate the memory for the filter table, it will send
a IND_FATAL and reset.

FIXME: should we add a field in IND_RESET to have the number of entry in the
filter table?

Debug
-----

### `0xE0 IND_CRC_ERROR`

Informative debug messages sent by the RCP when it receive a CRC error. The host
may try to match the `len` and `hcs` fields and send the frame again. However,
there is no way to recover the error of `hdr_error` is set.

 - `bool hdr_error`  
    If true the error was in the header field. After an `hdr_error`, the RCP
    will scan the UART data until it find a new valid header. The subsequent
    UART error are not reported.

 - `uint16_t len`  
    The copy of the `len` field as received in the frame header. If `hdr_error`
    is set, this field is not reliable.

 - `uint16_t hcs`  
    The copy of the `hcs` field as received in the frame header. If `hdr_error`
    is set, this field is not reliable.

### `0xE1 REQ_PING`

Send some arbitrary data to the device. The device will reply with `CNF_PING`. Use
this command to stress and debug the link with the device.

 - `uint16_t counter`  
    Arbitrary value (usually an incrementing counter that will be send back in
    confirmation).

 - `uint16_t reply_payload_size`  
    Size of the payload in the `CNF_PING`

 - `uint16_t payload_size`  
    Size of the next field

 - `uint8_t payload[]`  
    Arbitrary data. Data is not interpreted by the RCP.

### `0xE2 CNF_PING`

Reply to `REQ_PING` with some arbitrary data.

 - `uint16_t counter`  
    `counter` received in `REQ_PING`.

 - `uint16_t payload_size`  
    Same as field `reply_payload_size` in `REQ_PING`. Also define the size of
    the next field.

 - `uint8_t payload[]`  
    Arbitrary data.

Simulation
-----------

### `0xF0 IND_REPLAY_TIMER`

Only for simulation purpose. The device will never send it.

### `0xF1 IND_REPLAY_SOCKET`

Only for simulation purpose. The device will never send it.


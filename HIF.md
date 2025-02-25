# RCP Hardware Interface

This document describes the Hardware Interface (HIF) for the Silicon Labs
Wi-SUN Radio Co-Processor (RCP). The RCP implements IEEE 802.15.4 frame
transmission and reception using Wi-SUN frequency hopping and this API
allows a host to control it using commands sent on a serial bus.

## Acronyms

| Acronym | Source        | Meaning
|---------|---------------|---------
| FHSS    |               | Frequency Hopping Spread Spectrum
| EUI-64  | IEEE RA       | [64-bit Extended Unique Identifier][eui64]
| CCA     | IEEE 802.15.4 | Clear Channel Assessment
| CSMA-CA | IEEE 802.15.4 | Carrier Sense Multiple Access with Collision Avoidance
| IE      | IEEE 802.15.4 | Information Element
| BT-IE   | Wi-SUN        | Broadcast Timing IE
| FFN     | Wi-SUN        | Full Function Node
| LFN     | Wi-SUN        | Limited Function Node
| LBS-IE  | Wi-SUN        | LFN Broadcast Schedule IE
| LBT-IE  | Wi-SUN        | LFN Broadcast Timing IE
| LND-IE  | Wi-SUN        | LFN Network Discovery IE
| LTO-IE  | Wi-SUN        | LFN Timing Offset IE
| LUS-IE  | Wi-SUN        | LFN Unicast Schedule IE
| LUTT-IE | Wi-SUN        | LFN Unicast Timing and Frame Type IE
| POM-IE  | Wi-SUN        | PHY Operating Modes IE
| US-IE   | Wi-SUN        | Unicast Schedule IE
| UTT-IE  | Wi-SUN        | Unicast Timing and Frame Type IE
| CPC     | Silicon Labs  | [Co-Processor Communication][cpc]
| HIF     | Silicon Labs  | Hardware Interface
| RAIL    | Silicon Labs  | [Radio Abstraction Interface Layer][rail]
| RCP     | Silicon Labs  | Radio Co-Processor

[eui64]: https://standards.ieee.org/products-programs/regauth/
[rail]:  https://docs.silabs.com/rail/latest/rail-start

## General observations

In this specification, the prefix used in the command means:
  - `REQ` (request): a command sent by the host to the device
  - `SET`: special case of `REQ` to configure the device
  - `CNF` (confirmation): a reply from the device to the host
  - `IND` (indication): a spontaneous frame from the device to the host

By default, requests do not receive confirmations, the only exceptions are
[`REQ_RADIO_LIST`][rf-get] and [`REQ_DATA_TX`][tx-req].

All the types used are little endian.

The type `bool` is a `uint8_t`, but only the LSB is interpreted. All the other
bits are reserved.

When a bit is reserved or unassigned, it must be set to 0 by the transmitter
and must be ignored by the receiver.

All strings are null-terminated.

All the version numbers are encoded using `uint32_t` with the following mask:
  - `0xFF000000` Major revision
  - `0x00FFFF00` Minor revision
  - `0x000000FF` Patch

All timestamps are based on the RCP timebase, measured in microseconds, with
the origin set at the device reset.

All channel numbers are defined as if there were no channel mask applied
(_ChanN = Chan0 + N * ChanSpacing_).

## Frame structure

The RCP can use the _Native UART_ or the [_CPC_ protocol][cpc]. With CPC, the
frame structure is defined by the CPC specification.

With Native UART, frames use the following structure, and use a CRC-16 for
error detection.

 - `uint16_t len`  
    Length of the `payload` field . Only the 11 least significant bits
    (`0x07FF`) are used. The 5 most significant bits (`0xF800`) must be
    ignored.

 - `uint16_t hcs`  
    [CRC-16/MCRF4XX][hcs] of the `len` field.

 - `uint8_t payload[]`  
    Frame payload.

 - `uint16_t fcs`  
    [CRC-A][fcs] of the `payload` field.

Regardless of the framing protocol used, the payload always has the following
structure:

 - `uint8_t cmd`  
    Command number.

 - `uint8_t body[]`  
    Command body.

[cpc]: https://docs.silabs.com/gecko-platform/latest/platform-cpc-overview
[hcs]: https://reveng.sourceforge.io/crc-catalogue/16.htm#crc.cat.crc-16-mcrf4xx
[fcs]: https://reveng.sourceforge.io/crc-catalogue/16.htm#crc.cat.crc-16-iso-iec-14443-3-a

## Administrative commands

[reset]: #0x03-req_reset

### `0x01 REQ_NOP`

No-operation. Can be used to synchronize UART communication.

 - `uint8_t garbage[]`  
    Data after command is ignored.

### `0x02 IND_NOP`

No-operation. Can be used to synchronize UART communication.

 - `uint8_t garbage[]`  
    Extra data may be included. It must be ignored.

### `0x03 REQ_RESET`

Hard reset the RCP. After this command, the host will receive `IND_RESET`.

 - `bool enter_bootloader`  
    If set to `true`, the bootloader will start instead of the RCP application.
    Use this option for flashing a new RCP firmware. For details on how to
    upload a firmware (typically using the XMODEM protocol over UART), refer to
    the bootloader documentation.

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
    EUI-64 flashed on the device

 - `uint8_t reserved[]`  
    Extra data may be included. For backward compatibility, it must be ignored.

### `0x05 IND_FATAL`

Commands do not send a reply upon success. If the RCP is misconfigured or
encounters a fatal error happens, it will reset. In such cases, a `IND_RESET`
message will be sent after `IND_FATAL`, providing details about the error.
This information can be used to display the error to the user for debugging
purposes.

 - `uint16_t error_code`  
    Refer to the table below for the detailed list of errors.

 - `char error_string[]`  
    Human-readable error message.

| Name                 | Value  | Description                                                 |
|----------------------|--------|-------------------------------------------------------------|
|`EBUG`                |`0x0000`| An assert was triggered, reach out Silicon Labs support.    |
|`ECRC`                |`0x0001`| A framing error was detected on the bus.                    |
|`EHIF`                |`0x0002`| A parsing error occured while processing a command.         |
|`ENOBTL`              |`0x0003`| The RCP was not compiled with a bootloader.                 |
|`ENORF`               |`0x0004`| The radio layer has not been started.                       |
|`ENOMEM`              |`0x0005`| Not enough memory available.                                |
|`EINVAL`              |`0x1000`| Invalid parameter (generic).                                |
|`EINVAL_HOSTAPI`      |`0x1001`| Incompatible host API version.                              |
|`EINVAL_PHY`          |`0x1002`| Invalid PHY selection.                                      |
|`EINVAL_TXPOW`        |`0x1003`| Invalid TX power.                                           |
|`EINVAL_REG`          |`0x1004`| Invalid regulation code ([`SET_RADIO_REGULATION`][rf-reg]). |
|`EINVAL_FHSS`         |`0x1005`| Invalid frequency hopping configuration (generic).          |
|`EINVAL_FHSS_TYPE`    |`0x1006`| Invalid FHSS type ([`REQ_DATA_TX`][tx-req]).                |
|`EINVAL_CHAN_MASK`    |`0x1007`| Invalid channel mask.                                       |
|`EINVAL_CHAN_FUNC`    |`0x1008`| Invalid channel function.                                   |
|`EINVAL_ASYNC_TXLEN`  |`0x1009`| Invalid asynchronous transmission maximum duration ([`SET_FHSS_ASYNC`][async]).|
|`EINVAL_HANDLE`       |`0x100a`| Invalid packet handle.                                      |
|`EINVAL_KEY_INDEX`    |`0x100b`| Invalid key index.                                          |
|`EINVAL_FRAME_LEN`    |`0x100c`| Invalid IEEE 802.15.4 frame length.                         |
|`EINVAL_FRAME_VERSION`|`0x100d`| Invalid IEEE 802.15.4 frame version.                        |
|`EINVAL_FRAME_TYPE`   |`0x100c`| Invalid IEEE 802.15.4 frame type.                           |
|`EINVAL_ADDR_MODE`    |`0x100e`| Invalid IEEE 802.15.4 address mode.                         |
|`EINVAL_SCF`          |`0x100f`| Invalid IEEE 802.15.4 security control field.               |
|`EINVAL_FRAME`        |`0x1010`| Invalid IEEE 802.15.4 frame (generic).                      |
|`EINVAL_CHAN_FIXED`   |`0x1011`| Invalid fixed channel.                                      |
|`ENOTSUP`             |`0x2000`| Unsupported feature (generic).                              |
|`ENOTSUP_FHSS_DEFAULT`|`0x2001`| Unsupported configuration mode for selected FHSS type ([`REQ_DATA_TX`][tx-req]).|

### `0x06 SET_HOST_API`

Informs the RCP of the host API version. If this command is not sent, the RCP
will assume that the API version is `2.0.0`. This command should be sent after
`IND_RESET` and before any other command.

 - `uint32_t api_version`  
    Must be at least `0x02000000`.

## Send and receive data

Only a subset of the IEEE 802.15.4 frame formats are supported for the needs of
Wi-SUN:

  - Frame type must be either `1` (data) or `2` (ack, [`CNF_DATA_TX`][tx-cnf]
    only).
  - Frame version must be `2`.
  - Source address mode must be `3`.
  - Destination address mode must be either `0` or `3`.
  - See ["Security"][sec] for limits on the auxiliary security header.

[cca]:    #channel-access-and-retries
[tx-req]: #0x10-req_data_tx
[tx-cnf]: #0x12-cnf_data_tx
[rx]:     #0x13-ind_data_rx

### Channel Access and Retries

In Wi-SUN, all transmissions require the use of Clear Channel Assessment (CCA),
but the way attempts are performed differs depending on the [FHSS type][fhss]
used.

Unicast and broadcast ***to FFNs*** use the IEEE 802.15.4 CSMA-CA algorithm
with the following parameters:

| IEEE 802.15.4 MAC PIB | Value | Description |
|-----------------------|-------|-------------|
| `macMinBe`            | `3`   | Minimum Backoff Exponent (BE) for CSMA-CA.
| `macMaxBe`            | `5`   | Maximum Backoff Exponent (BE) for CSMA-CA.
| `macMaxCsmaBackoffs`  | `8`   | Number of CSMA-CA backoffs to attempt before declaring failure.
| `macMaxFrameRetries`  | `19`  | Number of retries allowed after a transmission failure.

Unicast and broadcast transmissions ***to LFNs*** can be conceived as if they
use the CSMA-CA algorithm, where the backoff is not randomized but instead
corresponds to the next available TX slot. This detail matters for counting
CCA failures versus transmission failures.

***Asynchronous*** transmissions use one CCA per channel, and skip the channel on
failure without attempting any retries. No overall CCA failure is returned in
[`CNF_DATA_TX`][tx-cnf] for these transmissions.

### `0x10 REQ_DATA_TX`

Sends a IEEE 802.15.4 frame. All data requests are followed by a data
confirmation ([`CNF_DATA_TX`][tx-cnf]) once the transaction is complete, even
in case of transmission failure or abort.

 - `uint8_t handle`  
    A unique arbitrary number used to identify a packet transmission in the
    RCP. Sent back in [`CNF_DATA_TX`][tx-cnf].

 - `uint16_t frame_len`  
    Length of the IEEE 802.15.4 frame to transmit.

 - `uint8_t frame[]`  
    An IEEE 802.15.4 frame without PHR and FCS. The RCP reads and interprets the
    header to determine what processing needs to be done. The frame must not be
    encrypted at this stage, see ["Security"][sec] for more details.

    If the following fields are present, they are automatically filled by the
    RCP (their input value is ignored and overwritten):
      - Sequence number
      - Timing parameters in Wi-SUN IEs (UTT, BT, LBT, LTO) (see
        ["FHSS Configuration"][fhss])
      - Frame counter (see ["Security"][sec])
      - Message Integrity Code (MIC) (see ["Security"][sec])

    <!-- TODO: Explain EDFE -->

 - `uint16_t flags`  
    A bitfield:
     - `0x0007 FHSS_TYPE_MASK`: Type of frequency hopping algorithm to use (see
        ["FHSS Configuration"][fhss]):
         - `0x00 FHSS_TYPE_FFN_UC`: Unicast to FFN
         - `0x01 FHSS_TYPE_FFN_BC`: Broadcast to FFN
         - `0x02 FHSS_TYPE_LFN_UC`: Unicast to LFN
         - `0x03 FHSS_TYPE_LFN_BC`: Broadcast to LFN
         - `0x04 FHSS_TYPE_ASYNC`:  Asynchronous
         - `0x06 FHSS_TYPE_LFN_PA`: LFN PAN Advertisement
     - `0x0010 FHSS_DEFAULT`:  
         - `0`: Schedule information is passed explicitly in this request.
            Supported with `FFN_UC`, `LFN_UC`, `LFN_PA`.
         - `1`: Use schedule information previously configured using a
            [`SET_FHSS`][fhss] command. Supported with `FFN_BC`, `LFN_BC`,
            `ASYNC`.
     - `0x0020 MODE_SWITCH`: Attempt mode switch with a list of specified PHYs.
       Only supported with `FHSS_TYPE_FFN_UC`.
     - `0x1fc0 FRAME_COUNTERS`: Bitmask of frame counters per key.
     - `0x2000 MODE_SWITCH_TYPE` (API >= 2.1.0):
       - `0`: PHY mode switch (PHR, default before API 2.1.0)
       - `1`: MAC mode switch (MAC command frame)
     - `0x4000 FRAME_COUNTER_8` (API >= 2.5.0): Frame includes frame counter for
       key at index 8.

Only present if `FHSS_TYPE_FFN_UC`:

 - `uint64_t utt_timestamp_us`  
    Timestamp associated with the last received UTT-IE from this node. The host
    will use the `timestamp_us` value from [`CNF_DATA_TX`][tx-cnf] and
    [`IND_DATA_RX`][rx].
 - `uint24_t ufsi` (from UTT-IE)
 - `uint8_t dwell_interval` (from US-IE)

Only present if `FHSS_TYPE_LFN_UC`:

 - `uint64_t lutt_timestamp_us`  
    Timestamp associated with the last received LUTT-IE from this node. The host
    will use the `timestamp_us` value from [`CNF_DATA_TX`][tx-cnf] and
    [`IND_DATA_RX`][rx].
 - `uint16_t slot` (from LUTT-IE)
 - `uint24_t interval_offset_ms` (from LUTT-IE)
 - `uint24_t interval_ms` (from LUS-IE)

Only present if `FHSS_TYPE_LFN_PA`:

 - `uint64_t lnd_timestamp_us`  
    Timestamp associated with the last received LND-IE from this node. The host
    will use the `timestamp_us` value from [`IND_DATA_RX`][rx].
 - `uint24_t response_delay_ms` (from LND-IE)
 - `uint8_t  slot_duration_ms` (from LND-IE)
 - `uint8_t  slot_count` (from LND-IE)
 - `uint16_t slot_first` (from LND-IE)

Other FHSS types have no additional fields.

Only present if `FHSS_DEFAULT == 0`:

 - `struct chan_seq`  
   See ["Channel Sequence"][chan-seq].

For each bit set in `FRAME_COUNTERS`:

 - `uint32_t frame_counter`  
   Minimum frame counter to accept when verifying acknowlegment frames. The
   associated key index maps to the bit offset (from 1 to 7). See
   ["Security"][sec].

Only present if `MODE_SWITCH`:

 - `struct rate_config[4]`  
    Fixed length and ordered array of rates to attempt until the transmission
    is successful, or all rates have been tried.
     - `uint8_t phy_mode_id`: Wi-SUN _PhyModeId_, must be in the group selected
        with [`SET_RADIO`][rf-set].
     - `uint8_t tx_attempts`: The maximum number of attempts allowed for this
        rate. Once this limit is exceeded, the next entry will be tried. Note
        that this valude overrides `macMaxFrameRetries` described in
        ["Channel Access and Retries"][cca].
     - `int8_t tx_power_dbm`: The TX power to use with this entry, saturates to
        the value configured with [`SET_RADIO_TX_POWER`][rf-pow].

Only present if `FRAME_COUNTER_8`:

   Same content as `FRAME_COUNTERS`, but only for key at index 8.
   See ["Security"][sec] for more details.

### `0x12 CNF_DATA_TX`

Status of an earlier data request ([`REQ_DATA_TX`][tx-req]). Also returns the
IEEE 802.15.4 acknowledgement frame if the request had the acknowledgement
request bit set in the header.

 - `uint8_t handle`  
    Frame handle, as provided in [`REQ_DATA_TX`][tx-req].

 - `uint8_t status`  
    See the table below for a list of status codes. The fields below may be
    invalid if `status != 0`.

 - `uint16_t frame_len`  
    Length of the IEEE 802.15.4 acknowledgment frame if received.

 - `uint8_t frame[]`  
    Decrypted IEEE 802.15.4 acknowledgment frame (see ["Security"][sec]).
    <!-- TODO: Explain EDFE. -->

 - `uint64_t timestamp_us`  
    The timestamp (relative to the date of the RCP reset) when the frame has
    been received.

 - `uint8_t lqi`  
    Received Link Quality Indicator (LQI) as reported by [RAIL][lqi] (ACK
    received only).

 - `int8_t rx_power_dbm`  
    Received power in dBm as reported by [RAIL][rssi] (ACK received only).

 - `uint32_t frame_counter`  
    Frame counter used in the successful transmission (see `frame_counter` in
    [`SET_SEC_KEY`][key]). Only valid if the request included an auxiliary
    security header.
    <!-- TODO: Return the last used frame counter, even if unsuccessful. -->

 - `uint16_t chan_num`  
    Channel number used in the successful transmission.

 - `uint8_t cca_failures`  
    Number of times channel access has failed consecutively (due to CCA failure
    or busy RX). For aknowledged frames, this counter is reset whenever the
    frame is transmitted on the radio but no acknowledgement is received.

 - `uint8_t tx_failures`  
    Number of transmission failures (does not account for CCA failures).

 - `uint8_t reserved`

Status codes:

| Value | Description
|-------|-------------
|`0x00` | Success.
|`0x01` | Not enough memory available.
|`0x02` | Channel access failure (CCA failure or busy RX).
|`0x03` | No ACK received (if ACK bit set in request).
|`0x04` | Frame spent too long in RCP (10s for unicast, 20s for broadcast, 40s for async, 300s for LFN).
|`0x05` | RCP internal error (reach out Silicon Labs support).

`0x06..0xff` are reserved for future errors. The host must accept these values and
consider the frame has not been received by the destination.

[lqi]:  https://docs.silabs.com/rail/latest/rail-api/rail-rx-packet-details-t#lqi
[rssi]: https://docs.silabs.com/rail/latest/rail-api/rail-rx-packet-details-t#rssi

### `0x13 IND_DATA_RX`

Receive IEEE 802.15.4 frames. The RCP will start emitting these indications
once the radio is started with [`SET_RADIO`][rf-set]. See
["Packet Filtering"][filter] to limit the amount of frames accepted.

 - `uint16_t frame_len`  
    Length of the received IEEE 802.15.4 frame.

 - `uint8_t frame[]`  
    Decrypted IEEE 802.15.4 frame, (see ["Security"][sec]).

 - `uint64_t timestamp_rx_us`  
    The timestamp (relative to the date of the RCP reset) when the frame has
    been received on the device.

 - `uint8_t lqi`  
    Received Link Quality Indicator (LQI) as reported by [RAIL][lqi].

 - `int8_t rx_power_dbm`  
    Received power in dBm as reported by [RAIL][rssi].

 - `uint8_t phy_mode_id`  
    Wi-SUN _PhyModeId_ used during reception.

 - `uint16_t chan_num`  
    Channel number used during reception.

## Radio configuration

PHY configuration and RCP level regional regulation enforcement. For
frequency hopping parameters, see ["FHSS configuration"][fhss].

[rf-get]:  #0x21-req_radio_list
[rf-list]: #0x22-cnf_radio_list
[rf-set]:  #0x23-set_radio
[rf-reg]:  #0x24-set_radio_regulation
[rf-pow]:  #0x25-set_radio_tx_power

### `0x20 REQ_RADIO_ENABLE`

Start the radio module. Before this, no packet can be transmitted
([`REQ_DATA_TX`][tx-req]) nor received ([`IND_DATA_RX`][rx]). Some
configuration needs to be done before calling this command, typically a PHY
must be selected with [`SET_RADIO`][rf-set], and a unicast schedule must be
configured with [`SET_FHSS_UC`][uc].

Body of this command is empty.

### `0x21 REQ_RADIO_LIST`

Request the list of radio configuration supported by the device, typically
issued by the host during a startup sequence before selecting a PHY
configuration. The RCP will answer with a series of [`CNF_RADIO_LIST`][rf-list]
commands.

Body of this command is empty.

### `0x22 CNF_RADIO_LIST`

List of radio configuration supported by the RCP, as configured during project
generation. Entries are defined in groups of mode-switch compatible PHYs. For
OFDM configurations, all MCS are defined in the same entry.

 - `uint8_t entry_size`  
    Size of a radio configuration entry in bytes. This is meant to support API
    evolution.

 - `bool list_end`  
    If not set, the list will continue in another [`CNF_RADIO_LIST`][rf-list].

 - `uint8_t count`  
    Number of radio configuration entries in next field.

 - `struct rf_config[]`  
    - `uint16_t flags`  
        - `0x0001`: If set, this entry is in same group than the previous.
        - `0x01FE`: Bitfield of supported OFDM MCS (from MCS0 to MCS11).
    - `uint8_t rail_phy_mode_id`  
       Wi-SUN _PhyModeId_. For OFDM, only the _PhyType_ is set, and MCS support
       is indicated in the `flags` field.
    - `uint32_t chan_f0`  
       Frequency of the first channel in Hz.
    - `uint32_t chan_spacing`  
       Channel spacing in Hz.
    - `uint16_t chan_count`  
       Number of channels without holes in the spectrum.
    - `uint16_t sensitivity` (API >= 2.4.0)  
       Minimum RX sensitivity in dBm for this PHY.

### `0x23 SET_RADIO`

Configure the radio parameters.

 - `uint8_t index`  
    Index in the `rf_config` list.

 - `uint8_t mcs`  
    MCS to be used if `index` points to an OFDM modulation.

 - `bool enable_mode_switch` (API > 2.0.1)  
    Enable mode switch in reception at PHY level (PHR), using all the PHY
    configurations available in the same group as the selected PHY. Note that
    mode switch cannot be disabled at MAC level (MAC command frame).

> [!NOTE]
> The host is responsible for advertising a list of supported _PhyModeId_ in a
> POM-IE. There may be more PHY supported in the RCP than advertised since the
> IE format restricts to 16 entries.

### `0x24 SET_RADIO_REGULATION`

Enable specific radio regulation rules. Most regulations only make sense with
specific channel configurations.

 - `uint32_t value`  
    - `0`: None (disabled, default)
    - `2`: Japan ([ARIB][arib])
    - `5`: India ([WPC][wpc])  

[arib]: https://www.arib.or.jp/
[wpc]:  https://dot.gov.in/spectrum-management/2457

### `0x25 SET_RADIO_TX_POWER`

 - `int8_t tx_power_dbm`  
    Maximum transmission power in dBm. The RCP may use a lower value based on
    internal decision making or hardware limitations but will never exceed the
    given value. The default value is 14dBm.

## Frequency Hopping (FHSS) configuration

Several schemes are used in Wi-SUN to transmit or receive packets using
frequency hopping. These are independently defined using a set of parameters
and may differ between transmission and reception. The following table
summarizes which commands configure the various FHSS parameters. Note that
[`REQ_DATA_TX`][tx-req] always needs to be called for transmission, but timing
parameters are sometimes passed with the command, and sometimes stored in the
RCP and configured once using a [`SET_FHSS`][fhss] command. See the description
of these commands for a more detailed explanation.

|  FHSS type                            | Location of FHSS parameters |
|---------------------------------------|-----------------------------|
| RX Unicast                            | [`SET_FHSS_UC`][uc]         |
| RX Broadcast                          | [`SET_FHSS_FFN_BC`][bc]     |
| TX Unicast to FFN                     | [`REQ_DATA_TX`][tx-req]     |
| TX Broadcast to FFN                   | [`SET_FHSS_FFN_BC`][bc]     |
| TX Unicast to LFN                     | [`REQ_DATA_TX`][tx-req]     |
| TX Unicast PAN Advert to LFN          | [`REQ_DATA_TX`][tx-req]     |
| TX Broadcast to LFN                   | [`SET_FHSS_LFN_BC`][bc-lfn] |
| TX Asynchronous (MLME-WS-ASYNC-FRAME) | [`SET_FHSS_ASYNC`][async]   |

In addition, the RCP is responsible for filling some timing related fields in
transmitted packets, based on active schedules:

  - UTT-IE (see [`SET_FHSS_UC`][uc]):
    - Unicast Fractional Sequence Interval (UFSI)
  - BT-IE (see [`SET_FHSS_FFN_BC`][bc]):
    - Broadcast Slot Number
    - Broadcast Interval Offset
  - LBT-IE (see [`SET_FHSS_LFN_BC`][bc-lfn]):
    - LFN Broadcast Slot Number
    - LFN Broadcast Interval Offset
  - LTO-IE:
    - Offset  
      The host sets this field as an offset relative to the start of the LFN
      broadcast window (see [`SET_FHSS_LFN_BC`][bc-lfn]). The RCP recomputes
      the offset to be relative to the destination LFN's unicast schedule,
      based on the timing information passed in [`REQ_DATA_TX`][tx-req].

### Channel Sequence

Most [`SET_FHSS`][fhss] commands configure a channel sequence using the
following variable-length structure:

 - `uint8_t chan_func`  
    Wi-SUN channel function, supported values are:
    - `0`: Single fixed channel. (API >= 2.1.1)
    - `2`: Direct Hash 1 (DH1CF) defined by Wi-SUN.

Only present if `chan_func == 0`:

  - `uint16_t chan_fixed`  
     Fixed channel number, valid range depends on the selected PHY.

Only present if `chan_func == 2`:

  - `uint8_t chan_mask_len`  
     Number of bytes in the following channel mask.

  - `uint8_t chan_mask[]`  
     Bitmask of used channels (1 for used, 0 for excluded). Channels are
     counted byte by byte, from least to most significant bit (channel `n` maps
     to `chan_mask[n / 8] & (1 << (n % 8))`). Integrators are responsible for
     meeting local regulation constraints by excluding disallowed channels from
     the selected PHY.

[fhss]:     #frequency-hopping-fhss-configuration
[chan-seq]: #channel-sequence
[uc]:       #0x30-set_fhss_uc
[bc]:       #0x31-set_fhss_ffn_bc
[bc-lfn]:   #0x32-set_fhss_lfn_bc
[async]:    #0x33-set_fhss_async

### `0x30 SET_FHSS_UC`

Configure unicast schedule for reception.

 - `uint8_t dwell_interval`  
    Unicast dwell interval in milliseconds (from US-IE).

 - `struct chan_seq`  
    See ["Channel Sequence"][chan-seq].

If API >= 2.6.0 (optional block):

 - `uint8_t ms_chan_mask_len`  
    Number of entries in the following `ms_chan_mask` array with
    one entry per channel spacing (i.e. per channel mask) supported for
    mode-switch.

 - `struct ms_chan_mask[]`  
    - `uint32_t channel_spacing_hz`  
       Channel spacing associated with the mask in Hertz.
    - `uint8_t chan_mask_len`  
       Number of bytes in the following channel mask.
    - `uint8_t chan_mask[]`  
       Mode switch channel mask. See the same field in
       ["Channel Sequence"][chan-seq] for more details.

### `0x31 SET_FHSS_FFN_BC`

Configure broadcast schedule for reception and transmission from/to FFN.

 - `uint32_t interval`  
    Broadcast interval in milliseconds (from BS-IE).

 - `uint16_t bsi`  
    Broadcast Schedule ID (from BS-IE).

 - `uint16_t dwell_interval`  
    Broadcast dwell interval in milliseconds (from BS-IE).

 - `struct chan_seq`  
   See ["Channel Sequence"][chan-seq].

If API >= 2.3.0 (optional block):

 - `uint8_t eui64[8]`  
    MAC address of a neighboring node whose broadcast schedule should be
    followed (typically a RPL parent or an EAPoL target). The RCP will read
    the BT-IE of frames received from that source address to maintain its
    broadcast schedule synchronized, which prevents needing to regularly update
    RCP timing from the host. By default, the address is set to
    `ff:ff:ff:ff:ff:ff:ff:ff`, which disables the parent following. Not
    including this block in the command also disables parent following. The
    next parameters set up the initial timings.

 - `uint64_t bt_timestamp_us`  
    Timestamp associated with the last received BT-IE from this node. The host
    will use the `timestamp_us` value from [`CNF_DATA_TX`][tx-cnf] and
    [`IND_DATA_RX`][rx].

 - `uint16_t slot`  
    Broadcast slot (from BT-IE).

 - `uint32_t interval_offset_ms`  
    Broadcast interval offset (from BT-IE).

 - `uint32_t frame_counters[4]`  
    Initial frame counters for this node for all keys (indices 1 through 4). As
    described in ["Security"][sec], the RCP generally does not check for frame
    counters since it is the responsability of the host. However this makes it
    easy to break the RCP broadcast schedule by replaying a frame containing a
    BT-IE. Thus the RCP can track the frame counters for a single parent. These
    counters are not reset when installing a new key, so it is recommended to
    always call [`SET_FHSS_FFN_BC`][bc] with updated counters right after
    calling [`SET_SEC_KEY`][key].

### `0x32 SET_FHSS_LFN_BC`

Configure broadcast schedule for transmission to LFN.

 - `uint16_t interval`  
    LFN broadcast interval in milliseconds (from LBS-IE).

 - `uint16_t bsi`  
    LFN broadcast Schedule ID (from LBS-IE).

 - `struct chan_seq`  
   See ["Channel Sequence"][chan-seq].

> [!WARNING]
> The current RCP implementation uses the same set of parameters for FFN and
> LFN broadcast channel sequences. Thus, [`SET_FHSS_FFN_BC`][bc] and
> [`SET_FHSS_LFN_BC`][bc-lfn] override each other's channel sequence. The other
> parameters are distinct.

> [!NOTE]
> The host is responsible for periodically sending LFN Time Sync frames in
> order to maintain broadcast timing in LFN children.

### `0x33 SET_FHSS_ASYNC`

Configure asynchronous transmissions for network discovery.

 - `uint32_t tx_duration_ms`  
    Maximum number of milliseconds the RCP is allowed to stay in continuous TX
    for an async transmission. If that duration is exceeded, the async
    transmission is split into chunks of that duration until all channels have
    been used. This mechanism makes the RCP radio available for other tasks
    between the async chunks, which becomes relevant for PHY configurations
    with many channels. By default, the value is set to `0xffffffff`, which
    disables this feature.

  - `uint8_t chan_mask_len`  
     Number of bytes in the following channel mask.

  - `uint8_t chan_mask[]`  
     Bitmask of channels to use for transmission. See the same field in
     ["Channel Sequence"][chan-seq] for more details.

## Security

> [!CAUTION]
> The RCP is responsible for encrypting and decrypting IEEE 802.15.4 frames.
> MAC layer data appears in cleartext in HIF commands so integrators are
> expected to secure the serial link, for example using
> [CPC with link encpryption][cpc-sec], otherwise the system may be exposed to
> packet injection or eavesdropping. IEEE 802.15.4 encryption keys can even be
> stolen if a malicious actor intercepts the HIF command which transfers them
> to the RCP.

To encrypt transmitted IEEE 802.15.4 frames, an auxiliary security header must
be included in the buffer passed to [`REQ_DATA_TX`](#0x10-req_data_tx), and
space must be reserved at the end of the frame for the Message Integrity Code
(MIC) depending on the security level. The packet payload is not yet encrypted
when passed to the RCP. The RCP is responsible for reading the auxiliary
security header, finding the associated key, filling the frame counter field,
encrypting the payload, and filling the MIC.

Similarly, the RCP decrypts received packets and provides them to host in
cleartext with [`IND_DATA_RX`](#0x13-ind_data_rx), with the auxiliary
security header untouched so that the host can process it.

> [!WARNING]
> The RCP does not verify the frame counter for received frames. It is the
> responsability of the host to maintain frame counters per key and per
> neighbor, and check them to prevent any replay attacks.

Acknowledgement frames are decrypted and sent to the host in the same manner
with the exception that the RCP does perform a frame counter check based on
the minimum values provided in the [`REQ_DATA_TX`](#0x10-req_data_tx) for that
packet.

> [!NOTE]
> Only a subset of the IEEE 802.15.4 security modes is supported. Wi-SUN uses
> security level `6` and key ID mode `1` with key indices 1 through 7. Frame
> counter is always used.

[sec]: #security
[key]: #0x40-set_sec_key
[cpc-sec]: https://github.com/SiliconLabs/cpc-daemon/blob/main/readme.md#encrypted-serial-link

### `0x40 SET_SEC_KEY`

Install a security key for encrypting/decrypting IEEE 802.15.4 frames.

 - `uint8_t key_index`  
    Key index to use. For API >= 2.5.0, only values from 1 to 8 (inclusive)
    are supported. For any older API version, only values from 1 to 7
    (inclusive) are supported.
    In the context of Wi-SUN, key at index 8 is reserved to
    [Silicon Labs' Direct Connect][dc] feature, if used.

 - `uint8_t key[16]`  
    Key in cleartext. If all zeroes, the key is un-installed.

 - `uint32_t frame_counter`  
    The initial frame counter value (for transmission). Should be 0 at first
    installation, should be positive on re-installation (after a RCP reboot).
    The RCP is responsible for incrementing the frame counter, and the value
    is communicated to the host in [`CNF_DATA_TX`](#0x12-cnf_data_tx) after
    each encrypted transmission.

[dc]: https://docs.silabs.com/wisun/latest/wisun-direct-connect

## Packet Filtering

Filter out received packets in the RCP to prevent unecessary
[`IND_DATA_RX`](#0x13-ind_data_rx) indications.

[filter]: #packet-filtering

### `0x58 SET_FILTER_PANID`

Refuse frames with an explicit PAN ID different from this value. By default,
the value is set to `0xffff` which disables the filter.

 - `uint16_t pan_id`  

### `0x5A SET_FILTER_SRC64`

Refuse frames based on the source MAC address. This should only be used in
specific testing scenarios to force network topologies. By default, the address
list is empty.

 - `bool allowed_list`  
   Instead of setting a list of denied address, set a list of allowed addresses
   where unknown ones are refused. Both ways are mutually exclusive and this
   command always resets the address list.

 - `uint8_t count`  
   Number of MAC addresses in the next field.

 - `uint8_t eui64[8][]`  
   List of MAC addresses (big endian) to deny/allow.

### `0x59 SET_FILTER_DST64`

Refuse unicast frames whose destination MAC address is not this EUI-64. By
default, the EUI-64 returned in [`IND_RESET`](#0x04-ind_reset) is used. This
filter cannot be disabled currently.

 - `uint8_t eui64[8]`  
    MAC address (big endian).

## Debug

[ping-req]: #0xe1-req_ping
[ping-cnf]: #0xe2-cnf_ping

### `0xE1 REQ_PING`

Send some arbitrary data to the device. The device will reply with
[`CNF_PING`][ping-cnf]. Use this command to stress and debug the serial link
with the device.

 - `uint16_t counter`  
    Arbitrary value (usually an incrementing counter that will be sent back in
    confirmation).

 - `uint16_t reply_payload_size`  
    Size of the payload in the [`CNF_PING`][ping-cnf].

 - `uint16_t payload_size`  
    Size of the `payload` field.

 - `uint8_t payload[]`  
    Arbitrary data. Data is not interpreted by the RCP.

### `0xE2 CNF_PING`

Reply to [`REQ_PING`][ping-req] with some arbitrary data.

 - `uint16_t counter`  
    `counter` received in [`REQ_PING`][ping-req].

 - `uint16_t payload_size`  
    Size of the `payload` field. Same value as the `reply_payload_size` field
    in [`REQ_PING`][ping-req].

 - `uint8_t payload[]`  
    Arbitrary data.

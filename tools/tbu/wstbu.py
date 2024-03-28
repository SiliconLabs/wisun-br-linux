import functools
import ipaddress
import multiprocessing
import operator
import os
import shutil
import socket
import struct
import sys
import time

import flask
import jsonschema
import sdbus
import systemd.journal
import yaml

import configutils
import utils
import wsbrd


with open('api.yaml') as f:
    g_api = yaml.safe_load(f)
    g_api = utils.resolve_refs(g_api)
config = None


#   Wi-SUN TBU REST API
# https://app.swaggerhub.com/apis/Wi-SUN/TestBedUnitAPI/1.1.10


# Wi-SUN TBU 1.0.18 {UDPDatagram,ICMPv6Echo}.frameExchangePattern
WSTBU_FRAME_EXCHANGE_DFE  = 0
WSTBU_FRAME_EXCHANGE_EDFE = 1


# Wi-SUN TBU 1.1.6 - BorderRouterInformationElement.format
WSTBU_IE_FORMAT_WH       = 0
WSTBU_IE_FORMAT_WP_SHORT = 1
WSTBU_IE_FORMAT_WP_LONG  = 2


# Wi-SUN TBU 1.1.10 - ICMPv6Echo.modeSwitch
# https://app.swaggerhub.com/apis/Wi-SUN/TestBedUnitAPI/1.1.10#/ICMPv6Echo
WSTBU_MODE_SWITCH_DISABLED = 0
WSTBU_MODE_SWITCH_PHY      = 1
WSTBU_MODE_SWITCH_MAC      = 2


# Wi-SUN TBU 1.0.18 ErrorResponse.code
WSTBU_ERR_UNKNOWN     = 0
WSTBU_ERR_CHAN_EXCL   = 1
WSTBU_ERR_RUN_MODE    = 2
WSTBU_ERR_NOT_BR      = 3
WSTBU_ERR_NOT_ROUTER  = 4
WSTBU_ERR_UNSUPPORTED = 5


# Wi-SUN Assigned Value Registry 0v24 - 10 Wi-SUN Frame Types
WS_FRAME_TYPE_PA    =  0
WS_FRAME_TYPE_PAS   =  1
WS_FRAME_TYPE_PC    =  2
WS_FRAME_TYPE_PCS   =  3
WS_FRAME_TYPE_DATA  =  4
WS_FRAME_TYPE_ACK   =  5
WS_FRAME_TYPE_EAPOL =  6
WS_FRAME_TYPE_LPA   =  9
WS_FRAME_TYPE_LPAS  = 10
WS_FRAME_TYPE_LPC   = 11
WS_FRAME_TYPE_LPCS  = 12
WS_FRAME_TYPE_EXT   = 15


# Wi-SUN Assigned Value Registry 0v24 - 7.1 Wi-SUN Header Information Element Sub-IDs
WS_WHIE_UTT   = 0x00
WS_WHIE_BT    = 0x01
WS_WHIE_FC    = 0x02
WS_WHIE_RSL   = 0x03
WS_WHIE_MHDS  = 0x04
WS_WHIE_VH    = 0x05
WS_WHIE_EA    = 0x09
WS_WHIE_LUTT  = 0x0a
WS_WHIE_LBT   = 0x0b
WS_WHIE_NR    = 0x0c
WS_WHIE_LUS   = 0x0d
WS_WHIE_FLUS  = 0x0e
WS_WHIE_LBS   = 0x0f
WS_WHIE_LND   = 0x10
WS_WHIE_LTO   = 0x11
WS_WHIE_PANID = 0x12


# Wi-SUN Assigned Value Registry 0v24 - 7.2 Wi-SUN Payload Information Element Sub-IDs
# Short form
WS_WPIE_PAN      = 0x04
WS_WPIE_NETNAME  = 0x05
WS_WPIE_PANVER   = 0x06
WS_WPIE_GTKHASH  = 0x07
WS_WPIE_POM      = 0x08
WS_WPIE_LBATS    = 0x09
WS_WPIE_JM       = 0x0a
WS_WPIE_LFNVER   = 0x40
WS_WPIE_LGTKHASH = 0x41
# Long form
WS_WPIE_US       = 0x01
WS_WPIE_BS       = 0x02
WS_WPIE_VP       = 0x03
WS_WPIE_LCP      = 0x04


# Wi-SUN FAN 1.1v06 - Figure 68c JM-IE Metric
WS_MASK_JM_ID  = 0b00111111
WS_MASK_JM_LEN = 0b11000000


def error(http_code: int, error_code: int, msg: str):
    return ({ 'code': error_code, 'message': msg }, http_code)


def success():
    return ('', 200)


def dbus_errcheck(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (
            sdbus.dbus_exceptions.DbusServiceUnknownError,
            sdbus.dbus_exceptions.DbusTimeoutError,
            sdbus.dbus_exceptions.DbusNoReplyError
        ) as e:
            return error(500, WSTBU_ERR_UNKNOWN, f'D-Bus error: {e}')
        except sdbus.sd_bus_internals.SdBusUnmappedMessageError as e:
            if e.args[0] in ['org.freedesktop.DBus.Error.TimedOut', 'System.Error.ENOTCONN']:
                return error(500, WSTBU_ERR_UNKNOWN, f'D-Bus error: {e.args[1]}')
            else:
                raise e
    return wrapper


def json_errcheck(path):
    schema = None
    for endpoint in g_api['paths'][path].values():
        if not schema:
            schema = endpoint['parameters'][0]['schema']
        else:
            # Ensure all methods use the same schema
            assert schema == endpoint['parameters'][0]['schema']
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                jsonschema.validate(flask.request.get_json(silent=True), schema)
            except jsonschema.ValidationError as e:
                return error(400, WSTBU_ERR_UNKNOWN, f'JSON error: {e.message}')
            return func(*args, **kwargs)
        return wrapper
    return decorator


# HACK: /config/borderRouter/joinMetrics may be called before /runMode/1
def wsbrd_set_join_metrics(jm_list, jm_version):
    if jm_list:
        jm_content = bytearray()
        jm_version = (jm_version + 1) % 256
        jm_content.append(jm_version)
        for jm_id in jm_list:
            jm_len, jm_data = jm_list[jm_id]
            jm_content.append(
                utils.field_prep(WS_MASK_JM_ID,  jm_id) |
                utils.field_prep(WS_MASK_JM_LEN, jm_len)
            )
            jm_content.extend(jm_data)
        wsbrd.dbus().ie_custom_insert(
            WSTBU_IE_FORMAT_WP_SHORT,
            WS_WPIE_JM,
            bytes(jm_content),
            bytes([WS_FRAME_TYPE_PA, WS_FRAME_TYPE_LPA])
        )
    else:
        wsbrd.dbus().ie_custom_insert(
            WSTBU_IE_FORMAT_WP_SHORT,
            WS_WPIE_JM,
            bytes(),
            bytes()
        )


@dbus_errcheck
def put_run_mode(mode: int):
    global jm_version, jm_list

    if mode == 0:
        wsbrd.service.stop('fail')
        wsbrd.config = wsbrd.config_default(config)
        try:
            os.remove('/ect/wstbu-dhcpv6-server.conf')
        except:
            pass
        jm_list = dict()
        jm_version = 0
    elif mode == 1:
        if not config.dhcpv6_server:
            return error(500, WSTBU_ERR_UNKNOWN, 'missing DHCPv6 server')
        configutils.write('/etc/wstbu-dhcpv6-relay.conf', dhcpv6_server=config.dhcpv6_server)
        configutils.write('/etc/wsbrd.conf', **wsbrd.config)
        wsbrd.service.start('fail')
        while wsbrd.service.active_state == 'activating':
            time.sleep(0.5)
        state = wsbrd.service.active_state
        if state == 'failed':
            j = systemd.journal.Reader()
            j.add_match(_SYSTEMD_UNIT='wisun-borderrouter.service')
            j.seek_tail()
            return error(500, WSTBU_ERR_UNKNOWN, j.get_previous()['MESSAGE'])
        elif state != 'active':
            return error(500, WSTBU_ERR_UNKNOWN, f'wisun-borderrouter.service {state}')
        # HACK: /config/borderRouter/joinMetrics may be called before /runMode/1
        wsbrd_set_join_metrics(jm_list, jm_version)
    else:
        return error(400, WSTBU_ERR_RUN_MODE, 'invalid run mode')
    return success()


@dbus_errcheck
@json_errcheck('/config/phy')
def put_config_phy():
    # Wi-SUN TBU 1.0.18 PhyConfig.modulation
    WSTBU_MOD_2FSK = 0
    # Wi-SUN TBU 1.0.18 PhyConfig.modulationIndex
    WSTBU_MOD_INDEX_0_5 = 0
    WSTBU_MOD_INDEX_1_0 = 1
    # Wi-SUN PHY 1v09 Table 2 - PHY Operating Modes and Symbol Rates
    WS_PHY_OP_MODE_TABLE = {
        ( 50000, WSTBU_MOD_INDEX_0_5): '1a',
        ( 50000, WSTBU_MOD_INDEX_1_0): '1b',
        (100000, WSTBU_MOD_INDEX_0_5): '2a',
        (100000, WSTBU_MOD_INDEX_1_0): '2b',
        (150000, WSTBU_MOD_INDEX_0_5):  '3',
        (200000, WSTBU_MOD_INDEX_0_5): '4a',
        (200000, WSTBU_MOD_INDEX_1_0): '4b',
        (300000, WSTBU_MOD_INDEX_0_5):  '5',
    }

    json = flask.request.get_json(force=True, silent=True)
    if wsbrd.service.active_state == 'active':
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation')
    if json['modulation'] != WSTBU_MOD_2FSK:
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported modulation')
    key = (json['symbolRate'], json['modulationIndex'])
    if key not in WS_PHY_OP_MODE_TABLE:
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported PHY config')
    wsbrd.config['mode'] = WS_PHY_OP_MODE_TABLE[key]
    return success()


@dbus_errcheck
@json_errcheck('/config/phy/modeID')
def put_config_phy_mode_id():
    json = flask.request.get_json(force=True, silent=True)
    if wsbrd.service.active_state == 'active':
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation')
    wsbrd.config['phy_mode_id'] = json['basePhyModeID']
    wsbrd.config['phy_operating_modes'] = 'auto' # Enable mode switch
    return success()


def config_chan_plan_reg_domain(json: dict):
    # Wi-SUN PHY 1v09 Table 3: Supported Frequency Bands and Channel Parameters
    WS_REG_DOMAIN_TABLE = {
        0x00: 'WW',
        0x01: 'NA',
        0x02: 'JP',
        0x03: 'EU',
        0x04: 'CN',
        0x05: 'IN',
        0x06: 'MX',
        0x07: 'BZ',
        0x08: 'AZ', # or NZ
        0x09: 'KR',
        0x0a: 'PH',
        0x0b: 'MY',
        0x0c: 'HK',
        0x0d: 'SG',
        0x0e: 'TH',
        0x0f: 'VN',
    }

    if json['regDomain'] not in WS_REG_DOMAIN_TABLE:
        return error(400, WSTBU_ERR_UNKNOWN, 'invalid domain')
    wsbrd.config['domain'] = WS_REG_DOMAIN_TABLE[json['regDomain']]
    return None


@dbus_errcheck
@json_errcheck('/config/chanPlan/regId')
def put_config_chan_plan_reg_id():
    json = flask.request.get_json(force=True, silent=True)
    if wsbrd.service.active_state == 'active':
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation')
    if err := config_chan_plan_reg_domain(json):
        return err
    wsbrd.config['chan_plan_id'] = json['chanPlanID']
    return success()


@dbus_errcheck
@json_errcheck('/config/chanPlan/regOp')
def put_config_chan_plan_reg_op():
    json = flask.request.get_json(force=True, silent=True)
    if json is None:
        return error(400, WSTBU_ERR_UNKNOWN, 'invalid JSON')
    if wsbrd.service.active_state == 'active':
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation')
    if err := config_chan_plan_reg_domain(json):
        return err
    wsbrd.config['class'] = json['opClass']
    return success()


@dbus_errcheck
@json_errcheck('/config/chanPlan/explicit')
def put_config_chan_plan_explicit():
    json = flask.request.get_json(force=True, silent=True)
    if wsbrd.service.active_state == 'active':
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation')
    wsbrd.config['chan0_freq']   = json['ch0']
    wsbrd.config['chan_spacing'] = json['chanSpacing']
    wsbrd.config['chan_count']   = json['numChans']
    return success()


@dbus_errcheck
@json_errcheck('/config/chanPlan/fixed')
def put_config_chan_plan_fixed():
    json = flask.request.get_json(force=True, silent=True)
    if wsbrd.service.active_state == 'active':
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation')
    wsbrd.config['allowed_channels'] = json['chanNumber']
    return success()


def config_chan_plan_common(json: dict):
    # Wi-SUN FAN 1.1v06 6.3.2.3.2.1.3 Field Definitions
    WS_CHAN_FUNC_FIXED  = 0
    WS_CHAN_FUNC_TR51   = 1
    WS_CHAN_FUNC_DH1    = 2
    WS_CHAN_FUNC_VENDOR = 3

    # Use /config/chanPlan/fixed for fixed channel
    if json['channelFunction'] != WS_CHAN_FUNC_DH1:
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported channel function')
    chan_excl_ranges = json.get('excludedChannelRange', [])
    chan_excl_mask   = json.get('excludedChannelMask', [])
    if chan_excl_ranges and chan_excl_mask:
        return error(400, WSTBU_ERR_CHAN_EXCL, 'both range and mask specified')
    if not chan_excl_mask and not chan_excl_ranges:
        return None

    # Convert excluded ranges to excluded mask
    if chan_excl_ranges:
        if len(chan_excl_ranges) % 2:
            return error(400, WSTBU_ERR_UNKNOWN, 'invalid channel exclusion range')
        it = iter(chan_excl_ranges)
        for min, max in zip(it, it):
            min = utils.parse_int(min)
            max = utils.parse_int(max)
            if min is None or max is None:
                return error(400, WSTBU_ERR_UNKNOWN, 'invalid channel exclusion range')
            if max < min:
                continue
            chan_excl_mask = utils.extend_to(chan_excl_mask, max + 1, False)
            for i in range(min, max + 1):
                chan_excl_mask[i] = True

    # Convert excluded mask to allowed ranges
    chan_allowed = []
    i_start = -1
    for i, excl in enumerate(chan_excl_mask):
        if not excl and i_start < 0:
            i_start = i
        elif excl and i_start >= 0:
            chan_allowed.append((i_start, i - 1))
            i_start = -1
    if i_start >= 0:
        chan_allowed.append((i_start, 255))

    wsbrd.config['allowed_channels'] = ','.join(
        f'{s}-{e}' for s, e in chan_allowed
    )
    return None


@dbus_errcheck
@json_errcheck('/config/chanPlan/unicast')
def put_config_chan_plan_unicast():
    json = flask.request.get_json(force=True, silent=True)
    if wsbrd.service.active_state == 'active':
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation')
    if err := config_chan_plan_common(json):
        return err
    wsbrd.config['unicast_dwell_interval'] = json['dwellInterval']
    return success()


@dbus_errcheck
@json_errcheck('/config/chanPlan/bcast')
def put_config_chan_plan_bcast():
    json = flask.request.get_json(force=True, silent=True)
    if wsbrd.service.active_state == 'active':
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation')
    if err := config_chan_plan_common(json):
        return err
    wsbrd.config['broadcast_interval']       = json['bcastInterval']
    wsbrd.config['broadcast_dwell_interval'] = json['dwellInterval']
    # TODO: handle BSI
    return success()


@dbus_errcheck
@json_errcheck('/config/chanPlan/bcast/lfn')
def put_config_chan_plan_bcast_lfn():
    json = flask.request.get_json(force=True, silent=True)
    if wsbrd.service.active_state == 'active':
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation')
    wsbrd.config['lfn_broadcast_interval']    = json['bcastInterval']
    wsbrd.config['lfn_broadcast_sync_period'] = json['bcastSyncPeriod']


@dbus_errcheck
@json_errcheck('/config/borderRouter')
def put_config_border_router():
    # Wi-SUN FAN 1.1v06 6.3.2.3.2.3 PAN Information Element (PAN-IE)
    WS_ROUTING_METHOD_MHDS = 0
    WS_ROUTING_METHOD_RPL  = 1

    json = flask.request.get_json(force=True, silent=True)
    if wsbrd.service.active_state == 'active':
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation')
    if not json['useParentBcastSched']:
        return error(500, WSTBU_ERR_UNSUPPORTED, 'unsupported use parent BS-IE disabled')
    if json['routingMethod'] != WS_ROUTING_METHOD_RPL:
        return error(500, WSTBU_ERR_UNSUPPORTED, 'unsupported routing method')
    wsbrd.config['pan_id']       = json['panId']
    wsbrd.config['pan_size']     = json['panSize']
    wsbrd.config['network_name'] = utils.escape_str(json['networkName'])
    if 'sixLowpanMtu' in json:
        wsbrd.config['lowpan_mtu'] = json['sixLowpanMtu']
    wsbrd.config['enable_lfn'] = json.get('lfnJoinEnabled', False)
    wsbrd.config['enable_ffn10'] = not wsbrd.config['enable_lfn']
    return success()


@dbus_errcheck
@json_errcheck('/config/borderRouter/gtks')
def put_config_border_router_gtks():
    def set_keys(json, key_name, key_count):
        keys = key_count * [None]
        for i in range(key_count):
            if f'{key_name}{i}' in json:
                keys[i] = utils.parse_key(json[f'{key_name}{i}'])
                if not keys[i] or keys[i] == bytes(16):
                    return error(400, WSTBU_ERR_UNKNOWN, 'invalid key')
        if wsbrd.service.active_state == 'active':
            keys_installed = getattr(wsbrd.dbus(), f'{key_name}s')
            keys_installed = tuple(map(lambda key: key if key != bytes(16) else None, keys_installed))
            assert functools.reduce(operator.__or__, map(bool, keys_installed)) # At least 1 key is installed

            for i in range(key_count):
                if keys[i] and keys_installed[i]:
                    return error(500, WSTBU_ERR_UNKNOWN, f'unsupported runtime operation: {key_name}{i} already installed')

            key_index_next = 0
            while not keys_installed[key_index_next]:
                key_index_next += 1
            while keys_installed[key_index_next]:
                key_index_next = (key_index_next + 1) % key_count

            key_queue = [] # Only insert keys once all indices are sanitized
            while functools.reduce(operator.__or__, map(bool, keys)):
                if not keys[key_index_next]:
                    return error(500, WSTBU_ERR_UNKNOWN, f'unsupported runtime operation: key index out of order (expected {key_name}{key_index_next})')
                key_queue.append(keys[key_index_next])
                keys[key_index_next] = None
                key_index_next = (key_index_next + 1) % key_count

            for key in key_queue:
                getattr(wsbrd.dbus(), f'install_{key_name}')(key)
        else:
            for i, key in enumerate(keys):
                if key:
                    wsbrd.config[f'{key_name}[{i}]'] = utils.format_key(key)
        return None
    json = flask.request.get_json(force=True, silent=True)
    if err := set_keys(json, 'gtk', 4):
        return err
    if err := set_keys(json, 'lgtk', 3):
        return err
    return success()


@dbus_errcheck
@json_errcheck('/config/borderRouter/keyLifetimes')
def put_config_border_router_key_lifetimes():
    json = flask.request.get_json(force=True, silent=True)
    if wsbrd.service.active_state == 'active':
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation')
    if 'pmkLifetime' in json:
        wsbrd.config['pmk_lifetime'] = json['pmkLifetime']
    if 'ptkLifetime' in json:
        wsbrd.config['ptk_lifetime'] = json['ptkLifetime']
    if 'gtkLifetime' in json:
        wsbrd.config['gtk_expire_offset'] = json['gtkLifetime']
    if 'gtkNewActivationTime' in json:
        wsbrd.config['gtk_new_activation_time'] = json['gtkNewActivationTime']
    if 'revocationLifetimeReduction' in json:
        wsbrd.config['ffn_revocation_lifetime_reduction'] = json['revocationLifetimeReduction']
    # TODO: support lfnPmkLifetime and lfnPtkLifetime
    if 'lgtkLifetime' in json:
        wsbrd.config['lgtk_expire_offset'] = json['lgtkLifetime']
    if 'lgtkNewActivationTime' in json:
        wsbrd.config['lgtk_new_activation_time'] = json['lgtkNewActivationTime']
    if 'lgtkRevocationLifetimeReduction' in json:
        wsbrd.config['lfn_revocation_lifetime_reduction'] = json['lgtkRevocationLifetimeReduction']
    return success()


@dbus_errcheck
@json_errcheck('/config/borderRouter/revokeKeys')
def put_config_border_router_revoke_keys():
    json = flask.request.get_json(force=True, silent=True)
    gtk = utils.parse_key(json['gtk'])
    if not gtk:
        return error(400, WSTBU_ERR_UNKNOWN, 'invalid key')
    # FIXME: only revoke GTKs or LGTKs, not both
    if json.get('isLgtk', False):
        wsbrd.dbus().revoke_group_keys(bytes(0), gtk)
    else:
        wsbrd.dbus().revoke_group_keys(gtk, bytes(0))
    return success()


@dbus_errcheck
@json_errcheck('/config/borderRouter/informationElements')
def config_border_router_information_elements():
    json = flask.request.get_json(force=True, silent=True)
    for json_ie in json:
        format = json_ie['format']
        sub_id = json_ie['subID']
        if flask.request.method == 'PUT':
            content = utils.parse_hexstr(json_ie.get('content', ''))
            if content is None:
                return error(400, WSTBU_ERR_UNKNOWN, 'invalid content')
            wsbrd.dbus().ie_custom_insert(format, sub_id, content, bytes([WS_FRAME_TYPE_PC]))
        elif flask.request.method == 'DELETE':
            wsbrd.dbus().ie_custom_insert(format, sub_id, bytes(), bytes())
    return success()


# Dict from JM-ID to tuple (len, data)
jm_list = dict()
jm_version = 0


@dbus_errcheck
@json_errcheck('/config/borderRouter/joinMetrics')
def config_border_router_join_metrics():
    global jm_list, jm_version

    json = flask.request.get_json(force=True, silent=True)
    jm_list_cpy = jm_list.copy() # Do not update the JM list before validation
    for json_jm in json:
        if json_jm['metricId'] > utils.field_max(WS_MASK_JM_ID):
            return error(500, WSTBU_ERR_UNKNOWN, 'invalid metric ID')
        if flask.request.method == 'PUT':
            jm_data = utils.parse_hexstr(json_jm.get('metricData', ''))
            if jm_data is None:
                return error(400, WSTBU_ERR_UNKNOWN, 'invalid metricData')
            if len(jm_data) == 0:
                jm_len = 0
            elif len(jm_data) == 1:
                jm_len = 1
            elif len(jm_data) == 2:
                jm_len = 2
            elif len(jm_data) == 4:
                jm_len = 3
            else:
                return error(500, WSTBU_ERR_UNKNOWN, 'invalid metricData')
            if 'metricLength' in json_jm and json_jm['metricLength'] != jm_len:
                return error(500, WSTBU_ERR_UNKNOWN, 'invalid length')
            jm_list_cpy[json_jm['metricId']] = (jm_len, jm_data)
        elif flask.request.method == 'DELETE':
            del jm_list_cpy[json_jm['metricId']]
    jm_list = jm_list_cpy
    # HACK: /config/borderRouter/joinMetrics may be called before /runMode/1
    if wsbrd.service.active_state == 'active':
        wsbrd_set_join_metrics(jm_list, jm_version)
    return success()


@dbus_errcheck
@json_errcheck('/config/borderRouter/externalResources')
def put_config_border_router_external_resources():
    global config

    if wsbrd.service.active_state == 'active':
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation')
    json = flask.request.get_json(force=True, silent=True)
    config.dhcpv6_server = utils.parse_ipv6(json['dhcpServerAddress'])
    if not config.dhcpv6_server:
        return error(400, WSTBU_ERR_UNKNOWN, 'invalid dhcpServerAddress')
    wsbrd.config['radius_server'] = json['authServerAddress']
    wsbrd.config['radius_secret'] = json['authServerSecret']
    return success()


@dbus_errcheck
@json_errcheck('/config/whitelist')
def put_config_whitelist():
    json = flask.request.get_json(force=True, silent=True)
    if wsbrd.service.active_state == 'active':
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation')
    if 'macAddressList' not in json:
        return
    wsbrd.config['allowed_mac64'] = json['macAddressList']
    return success()


def put_config_router():
    return error(400, WSTBU_ERR_NOT_ROUTER, 'unsupported endpoint')


sub_process = None


def subscription_frame_forward(family, sockaddr):
    ''' Read from the pcap capture FIFO and send into a UDP stream.'''

    sub_fifo = os.open(config.fifo_path, os.O_RDONLY)
    with socket.socket(family, socket.SOCK_DGRAM) as sck:
        while True:
            data = os.read(sub_fifo, 2000)
            sck.sendto(data, sockaddr)


@json_errcheck('/subscription/frames')
def put_subscription_frame():
    global sub_process

    json = flask.request.get_json(force=True, silent=True)
    if json['subscriptionMode'] == 'Start':
        addr = json['fwdAddress']
        port = json['fwdPort']
        try:
            addrinfo = socket.getaddrinfo(addr, port, proto=socket.IPPROTO_UDP)
        except socket.gaierror as e:
            return error(500, WSTBU_ERR_UNKNOWN, f'getaddrinfo(address={addr}, port={port}): {e}')
        family, _, _, _, sockaddr = addrinfo[0]
        if sub_process and sub_process.is_alive():
            sub_process.terminate()
        sub_process = multiprocessing.Process(
            target=subscription_frame_forward,
            args=(family, sockaddr),
            daemon=True
        )
        sub_process.start()
    elif json['subscriptionMode'] == 'Stop':
        if sub_process and sub_process.is_alive():
            sub_process.terminate()
    else:
        return error(400, WSTBU_ERR_UNKNOWN, 'invalid subscription mode')
    return success()


def get_subscription_frame_hash():
    return error(501, WSTBU_ERR_UNSUPPORTED, 'unsupported endpoint')


def transmitter_sendmsg(
    sck:      socket.socket,
    src_addr: ipaddress.IPv6Address,
    dst_addr: ipaddress.IPv6Address,
    data:     bytes,
    src_port: int  = 0,
    dst_port: int  = 0,
    cmsg:     list = [],
):
    ifname = config.tun_device
    try:
        sck.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bytes(ifname, 'ascii'))
    except OSError as e:
        return error(500, WSTBU_ERR_UNKNOWN, f'setsockopt(SO_BINDTODEVICE, ifname={ifname}): {e}')
    try:
        sck.bind((str(src_addr), src_port))
    except OSError as e:
        return error(500, WSTBU_ERR_UNKNOWN, f'bind(addr={src_addr} port={src_port}): {e}')
    if dst_addr.is_multicast:
        try:
            wsbrd.dbus().join_multicast_group(dst_addr.packed)
        except sdbus.dbus_exceptions.DbusAddressInUseError:
            pass
    try:
        sck.sendmsg([data], cmsg, 0, (str(dst_addr), dst_port))
    except OSError as e:
        return error(500, WSTBU_ERR_UNKNOWN, f'sendmsg(addr={dst_addr}, port={dst_port}): {e}')
    return None


@json_errcheck('/transmitter/udp')
def put_transmitter_udp():
    json = flask.request.get_json(force=True, silent=True)
    if json['frameExchangePattern'] != WSTBU_FRAME_EXCHANGE_DFE:
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported frame exchange pattern')
    src_addr = utils.parse_ipv6(json['srcAddress'])
    dst_addr = utils.parse_ipv6(json['destAddress'])
    if not src_addr or not dst_addr:
        return error(400, WSTBU_ERR_UNKNOWN, 'invalid address')
    src_port = json['srcPort']
    dst_port = json['destPort']
    data = bytes(json['data'], 'utf-8')

    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sck:
        if err := transmitter_sendmsg(sck, src_addr, dst_addr, data, src_port, dst_port):
            return err
    return success()


@dbus_errcheck
@json_errcheck('/transmitter/icmpv6Echo')
def put_transmitter_icmpv6():
    json = flask.request.get_json(force=True, silent=True)
    if json['frameExchangePattern'] != WSTBU_FRAME_EXCHANGE_DFE:
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported frame exchange pattern')
    src_addr = utils.parse_ipv6(json['srcAddress'])
    dst_addr = utils.parse_ipv6(json['destAddress'])
    if not src_addr or not dst_addr:
        return error(400, WSTBU_ERR_UNKNOWN, 'invalid address')

    dst_eui64 = bytes()
    for eui64, properties in wsbrd.dbus().nodes:
        if not properties.get('is_neighbor', ('b', False))[1]:
            continue
        if 'ipv6' not in properties:
            continue
        assert properties['ipv6'][0] == 'aay'
        for addr in properties['ipv6'][1]:
            if ipaddress.IPv6Address(addr) == dst_addr:
                dst_eui64 = eui64
                break
    if not dst_eui64:
        utils.warn(f'no known EUI-64 for destAddress={dst_addr}: mode switch configured globally')

    ms_mode = json.get('modeSwitch', WSTBU_MODE_SWITCH_DISABLED)
    if ms_mode == WSTBU_MODE_SWITCH_PHY:
        if 'phyModeID' not in json:
            return error(400, WSTBU_ERR_UNKNOWN, 'missing phyModeID')
        phy_mode_id = json['phyModeID']
    elif ms_mode == WSTBU_MODE_SWITCH_DISABLED:
        phy_mode_id = -1
    else:
        return error(500, WSTBU_ERR_UNKNOWN, f'unsupported modeSwitch={ms_mode}')
    try:
        wsbrd.dbus().set_mode_switch(dst_eui64, phy_mode_id)
    except sdbus.dbus_exceptions.DbusInvalidArgsError:
        return error(400, WSTBU_ERR_UNKNOWN, f'invalid phyModeID')

    # RFC 4443 - 4.1. Echo Request Message
    data = struct.pack('!BBHHH',
        128,                       # Type
        0,                         # Code
        0,                         # Checksum
        json.get('identifier'),    # Identifier
        json.get('sequenceNumber') # Sequence Number
    )
    data += bytes(json.get('data', ''), 'utf-8')
    cmsg = [(socket.IPPROTO_IPV6, socket.IPV6_HOPLIMIT, struct.pack('i', json['hopLimit']))]

    with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as sck:
        if err := transmitter_sendmsg(sck, src_addr, dst_addr, data, cmsg=cmsg):
            return err
    return success()


@dbus_errcheck
def get_config_ip_addresses():
    # Wi-SUN FAN 1.1v06 6.3.2.3.1.10 Node Role Information Element (NR-IE)
    WS_NODE_ROLE_BR     = 0
    WS_NODE_ROLE_ROUTER = 1
    WS_NODE_ROLE_LFN    = 2

    for _, properties in wsbrd.dbus().nodes:
        if properties.get('node_role') != WS_NODE_ROLE_BR:
            continue
        if 'ipv6' in properties:
            assert properties['ipv6'][0] == 'aay'
            return [str(ipaddress.IPv6Address(addr)) for addr in properties['ipv6'][1]]
    return []


@dbus_errcheck
def get_config_security_keys():
    gtks = dict()
    for i, gtk in enumerate(wsbrd.dbus().gtks):
        if gtk != bytes(16):
            gtks[f'gtk{i}'] = utils.format_key(gtk)
    for i, gtk in enumerate(wsbrd.dbus().lgtks):
        if gtk != bytes(16):
            gtks[f'lgtk{i}'] = utils.format_key(gtk)
    return gtks


@dbus_errcheck
def get_config_dodag_routes():
    routes = []
    for _, properties in wsbrd.dbus().nodes:
        if 'parent' not in properties:
            continue
        if 'ipv6' not in properties:
            continue
        assert properties['ipv6'][0] == 'aay'
        for addr in properties['ipv6'][1]:
            addr = ipaddress.IPv6Address(addr)
            if not addr.is_link_local:
                routes.append({'route': str(addr)})
    return routes


@dbus_errcheck
def get_config_preferred_parent():
    addr = utils.parse_ipv6(flask.request.args.get('ipAddress'))
    if not addr:
        return error(400, WSTBU_ERR_UNKNOWN, 'invalid address')
    nodes = wsbrd.dbus().nodes
    parent_eui64 = None
    for _, properties in nodes:
        if 'ipv6' not in properties:
            continue
        assert properties['ipv6'][0] == 'aay'
        if addr.packed not in properties['ipv6'][1]:
            continue
        parent_eui64 = properties.get('parent', ('ay', bytes()))[1]
    if not parent_eui64:
        return error(500, WSTBU_ERR_UNKNOWN, 'no known parent')
    for eui64, properties in nodes:
        if eui64 != parent_eui64:
            continue
        # Parent should always have an IPv6 address
        assert properties['ipv6'][0] == 'aay'
        for addr in properties['ipv6'][1]:
            addr = ipaddress.IPv6Address(addr)
            if not addr.is_link_local:
                return flask.json.jsonify(str(addr))
    return error(500, WSTBU_ERR_UNKNOWN, 'parent has no address')


def get_config_neighbor_table():
    return error(501, WSTBU_ERR_UNKNOWN, 'unsupported endpoint')


@dbus_errcheck
def get_capabilities_phy(eui64: str):
    eui64 = utils.parse_eui64(eui64)
    if not eui64:
        return error(400, WSTBU_ERR_UNKNOWN, 'invalid eui64')
    for _eui64, properties in wsbrd.dbus().nodes:
        if _eui64  != eui64:
            continue
        res = dict()
        res['mdrCmdCapable'] = properties.get('mdr_cmd_capable', ('b', False))[1]
        res['phyOpModes'] = [int(pom) for pom in properties.get('pom', ('ay', bytes()))[1]]
        return res
    return error(400, WSTBU_ERR_UNKNOWN, 'unknown eui64')


def app_build():
    app = flask.Flask(__name__)
    app.add_url_rule('/runMode/<int:mode>',                      view_func=put_run_mode,                                methods=['PUT'])
    app.add_url_rule('/config/phy',                              view_func=put_config_phy,                              methods=['PUT'])
    app.add_url_rule('/config/phy/modeID',                       view_func=put_config_phy_mode_id,                      methods=['PUT'])
    app.add_url_rule('/config/chanPlan/regId',                   view_func=put_config_chan_plan_reg_id,                 methods=['PUT'])
    app.add_url_rule('/config/chanPlan/regOp',                   view_func=put_config_chan_plan_reg_op,                 methods=['PUT'])
    app.add_url_rule('/config/chanPlan/explicit',                view_func=put_config_chan_plan_explicit,               methods=['PUT'])
    app.add_url_rule('/config/chanPlan/fixed',                   view_func=put_config_chan_plan_fixed,                  methods=['PUT'])
    app.add_url_rule('/config/chanPlan/unicast',                 view_func=put_config_chan_plan_unicast,                methods=['PUT'])
    app.add_url_rule('/config/chanPlan/bcast',                   view_func=put_config_chan_plan_bcast,                  methods=['PUT'])
    app.add_url_rule('/config/chanPlan/bcast/lfn',               view_func=put_config_chan_plan_bcast_lfn,              methods=['PUT'])
    app.add_url_rule('/config/borderRouter',                     view_func=put_config_border_router,                    methods=['PUT'])
    app.add_url_rule('/config/borderRouter/gtks',                view_func=put_config_border_router_gtks,               methods=['PUT'])
    app.add_url_rule('/config/borderRouter/keyLifetimes',        view_func=put_config_border_router_key_lifetimes,      methods=['PUT'])
    app.add_url_rule('/config/borderRouter/revokeKeys',          view_func=put_config_border_router_revoke_keys,        methods=['PUT'])
    app.add_url_rule('/config/borderRouter/informationElements', view_func=config_border_router_information_elements,   methods=['PUT', 'DELETE'])
    app.add_url_rule('/config/borderRouter/joinMetrics',         view_func=config_border_router_join_metrics,           methods=['PUT', 'DELETE'])
    app.add_url_rule('/config/borderRouter/externalResources',   view_func=put_config_border_router_external_resources, methods=['PUT'])
    app.add_url_rule('/config/router',                           view_func=put_config_router,                           methods=['PUT'])
    app.add_url_rule('/config/whitelist',                        view_func=put_config_whitelist,                        methods=['PUT'])
    app.add_url_rule('/subscription/frames',                     view_func=put_subscription_frame,                      methods=['PUT'])
    app.add_url_rule('/subscription/frames/hash',                view_func=get_subscription_frame_hash,                 methods=['GET'])
    app.add_url_rule('/transmitter/udp',                         view_func=put_transmitter_udp,                         methods=['PUT'])
    app.add_url_rule('/transmitter/icmpv6Echo',                  view_func=put_transmitter_icmpv6,                      methods=['PUT'])
    app.add_url_rule('/config/ipAddresses',                      view_func=get_config_ip_addresses,                     methods=['GET'])
    app.add_url_rule('/config/securityKeys',                     view_func=get_config_security_keys,                    methods=['GET'])
    app.add_url_rule('/config/dodagRoutes',                      view_func=get_config_dodag_routes,                     methods=['GET'])
    app.add_url_rule('/config/preferredParent',                  view_func=get_config_preferred_parent,                 methods=['GET'])
    app.add_url_rule('/config/neighborTable',                    view_func=get_config_neighbor_table,                   methods=['GET'])
    app.add_url_rule('/capabilities/phy/<string:eui64>',         view_func=get_capabilities_phy,                        methods=['GET'])
    return app


def main():
    global config

    if os.getuid() != 0:
        utils.fatal('server must be run as root')
    if len(sys.argv) != 2:
        utils.fatal(f'usage: {sys.argv[0]} config.ini')

    config = configutils.read_wstbu(sys.argv[1])
    shutil.rmtree(config.tmp_dir, ignore_errors=True)
    os.mkdir(config.tmp_dir)
    os.mkdir(config.nvm_dir)
    os.mkfifo(config.fifo_path)
    wsbrd.config = wsbrd.config_default(config)
    wsbrd.service.stop('fail')

    app = app_build()
    app.run(host='0.0.0.0', port=config.wstbu_port)


if __name__ == '__main__':
    main()

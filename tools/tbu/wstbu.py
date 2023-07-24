import functools
import ipaddress
import os
import select
import shutil
import socket
import struct
import sys
import time
import threading

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
# https://app.swaggerhub.com/apis/Wi-SUN/TestBedUnitAPI/1.0.18


# Wi-SUN TBU 1.0.18 {UDPDatagram,ICMPv6Echo}.frameExchangePattern
WSTBU_FRAME_EXCHANGE_DFE  = 0
WSTBU_FRAME_EXCHANGE_EDFE = 1


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


@dbus_errcheck
def put_run_mode(mode: int):
    if mode == 0:
        wsbrd.service.stop('fail')
        wsbrd.config = wsbrd.config_default(config)
    elif mode == 1:
        configutils.write('/etc/wsbrd.conf', wsbrd.config)
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
    json = flask.request.get_json(force=True, silent=True)
    gtks = 4 * [None]
    for i in range(4):
        if f'gtk{i}' in json:
            gtks[i] = utils.parse_key(json[f'gtk{i}'])
            if not gtks[i]:
                return error(400, WSTBU_ERR_UNKNOWN, 'invalid key')
    if wsbrd.service.active_state == 'active':
        i = -1
        for j, gtk in enumerate(gtks):
            if gtk:
                if i > 0:
                    return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation: more than 1 key')
                i = j
        if i < 0:
            return
        gtks_cur = wsbrd.dbus().gtks
        if gtks_cur[i] != bytes(16):
            return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation: key already installed')
        if gtks_cur[(i + 3) % 4] == bytes(16):
            return error(500, WSTBU_ERR_UNKNOWN, 'unsupported runtime operation: previous key not installed')
        wsbrd.dbus().install_gtk(gtks[i])
    else:
        for i, gtk in enumerate(gtks):
            if gtk:
                wsbrd.config[f'gtk[{i}]'] = utils.format_key(gtk)
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
        wsbrd.config['pmk_lifetime'] = json['ptkLifetime']
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


sub_thread = None
sub_fifo = None


def subscription_frame_forward(family, sockaddr):
    ''' Read from the pcap capture FIFO and send into a UDP stream.'''
    global sub_fifo

    sub_fifo = os.open(config.fifo_path, os.O_RDONLY)
    poll = select.poll()
    poll.register(sub_fifo, select.POLLIN)
    with socket.socket(family, socket.SOCK_DGRAM) as sck:
        while True:
            revents = poll.poll()[0][1]
            if revents & select.POLLIN:
                data = os.read(sub_fifo, 2000)
                sck.sendto(data, sockaddr)
            elif revents & select.POLLHUP:
                return


@json_errcheck('/subscription/frames')
def put_subscription_frame():
    global sub_thread
    global sub_fifo

    json = flask.request.get_json(force=True, silent=True)
    if json['subscriptionMode'] == 'Start':
        addr = json['fwdAddress']
        port = json['fwdPort']
        try:
            addrinfo = socket.getaddrinfo(addr, port, proto=socket.IPPROTO_UDP)
        except socket.gaierror as e:
            return error(500, WSTBU_ERR_UNKNOWN, f'getaddrinfo(address={addr}, port={port}): {e}')
        family, _, _, _, sockaddr = addrinfo[0]
        if sub_fifo:
            os.close(sub_fifo)
            sub_fifo = None
            sub_thread.join()
            sub_thread = None
        if not sub_thread:
            sub_thread = threading.Thread(
                target=subscription_frame_forward,
                args=(family, sockaddr),
                daemon=True
            )
            sub_thread.start()
    elif json['subscriptionMode'] == 'Stop':
        if sub_thread:
            os.close(sub_fifo)
            sub_fifo = None
            sub_thread.join()
            sub_thread = None
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


@json_errcheck('/transmitter/icmpv6Echo')
def put_transmitter_icmpv6():
    json = flask.request.get_json(force=True, silent=True)
    if json['frameExchangePattern'] != WSTBU_FRAME_EXCHANGE_DFE:
        return error(500, WSTBU_ERR_UNKNOWN, 'unsupported frame exchange pattern')
    src_addr = utils.parse_ipv6(json['srcAddress'])
    dst_addr = utils.parse_ipv6(json['destAddress'])
    if not src_addr or not dst_addr:
        return error(400, WSTBU_ERR_UNKNOWN, 'invalid address')

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
        if addr not in properties['ipv6'][1]:
            continue
        parent_eui64 = properties.get('parent')
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
                return str(addr)
    return error(500, WSTBU_ERR_UNKNOWN, 'parent has no address')


def get_config_neighbor_table():
    return error(501, WSTBU_ERR_UNKNOWN, 'unsupported endpoint')


def app_build():
    app = flask.Flask(__name__)
    app.add_url_rule('/runMode/<int:mode>',                      view_func=put_run_mode,                              methods=['PUT'])
    app.add_url_rule('/config/phy',                              view_func=put_config_phy,                            methods=['PUT'])
    app.add_url_rule('/config/phy/modeID',                       view_func=put_config_phy_mode_id,                    methods=['PUT'])
    app.add_url_rule('/config/chanPlan/regId',                   view_func=put_config_chan_plan_reg_id,               methods=['PUT'])
    app.add_url_rule('/config/chanPlan/regOp',                   view_func=put_config_chan_plan_reg_op,               methods=['PUT'])
    app.add_url_rule('/config/chanPlan/explicit',                view_func=put_config_chan_plan_explicit,             methods=['PUT'])
    app.add_url_rule('/config/chanPlan/fixed',                   view_func=put_config_chan_plan_fixed,                methods=['PUT'])
    app.add_url_rule('/config/chanPlan/unicast',                 view_func=put_config_chan_plan_unicast,              methods=['PUT'])
    app.add_url_rule('/config/chanPlan/bcast',                   view_func=put_config_chan_plan_bcast,                methods=['PUT'])
    app.add_url_rule('/config/borderRouter',                     view_func=put_config_border_router,                  methods=['PUT'])
    app.add_url_rule('/config/borderRouter/gtks',                view_func=put_config_border_router_gtks,             methods=['PUT'])
    app.add_url_rule('/config/borderRouter/keyLifetimes',        view_func=put_config_border_router_key_lifetimes,    methods=['PUT'])
    app.add_url_rule('/config/borderRouter/revokeKeys',          view_func=put_config_border_router_revoke_keys,      methods=['PUT'])
    app.add_url_rule('/config/borderRouter/informationElements', view_func=config_border_router_information_elements, methods=['PUT', 'DELETE'])
    app.add_url_rule('/config/router',                           view_func=put_config_router,                         methods=['PUT'])
    app.add_url_rule('/config/whitelist',                        view_func=put_config_whitelist,                      methods=['PUT'])
    app.add_url_rule('/subscription/frames',                     view_func=put_subscription_frame,                    methods=['PUT'])
    app.add_url_rule('/subscription/frames/hash',                view_func=get_subscription_frame_hash,               methods=['GET'])
    app.add_url_rule('/transmitter/udp',                         view_func=put_transmitter_udp,                       methods=['PUT'])
    app.add_url_rule('/transmitter/icmpv6Echo',                  view_func=put_transmitter_icmpv6,                    methods=['PUT'])
    app.add_url_rule('/config/ipAddresses',                      view_func=get_config_ip_addresses,                   methods=['GET'])
    app.add_url_rule('/config/securityKeys',                     view_func=get_config_security_keys,                  methods=['GET'])
    app.add_url_rule('/config/dodagRoutes',                      view_func=get_config_dodag_routes,                   methods=['GET'])
    app.add_url_rule('/config/preferredParent',                  view_func=get_config_preferred_parent,               methods=['GET'])
    app.add_url_rule('/config/neighborTable',                    view_func=get_config_neighbor_table,                 methods=['GET'])
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

#
# SPDX-License-Identifier: LicenseRef-MSLA
# Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
#
# The licensor of this software is Silicon Laboratories Inc. Your use of this
# software is governed by the terms of the Silicon Labs Master Software License
# Agreement (MSLA) available at [1].  This software is distributed to you in
# Object Code format and/or Source Code format and is governed by the sections
# of the MSLA applicable to Object Code, Source Code and Modified Open Source
# Code. By using this software, you agree to the terms of the MSLA.
#
# [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
#
import ipaddress
import typing


def fatal(msg: str) -> typing.NoReturn:
    print(f'\x1b[31mfatal: {msg}\x1b[0m')
    exit(1)


def warn(msg):
    print(f'\x1b[33mwarn: {msg}\x1b[0m')


def extend_to(lst: list, size: int, fill) -> list:
    '''Grow lst to size using fill value. Identity if lst is already big enough.'''
    if size > len(lst):
        return lst + (size - len(lst)) * [fill]
    else:
        return lst


def escape_str(string: str) -> str:
    '''
    Subsitute non-alphanumeric characters with an escaped form with backslash x
    followed by their ascii hexadecimal value.
    Example: r"Hello, world!" -> r"Hello\x2c\x5fworld\x21"
    '''
    return ''.join(
        c if c.isalnum()
        else f'\\x{ord(c):02x}'
        for c in string
    )


def format_key(key: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in key)


def parse_hexstr(string: str, separators=[], len_check=0) -> typing.Optional[bytes]:
    if not isinstance(string, str):
        return None
    try:
        res = bytes(int(string[i:(i + 2)], 16) for i in range(0, len(string), 2))
        return res if len(res) == len_check or not len_check else None
    except:
        pass
    for separator in separators:
        try:
            res = bytes(int(s, 16) for s in string.split(separator))
            return res if len(res) == len_check or not len_check else None
        except:
            pass
    return None


def parse_key(key: str) -> typing.Optional[bytes]:
    return parse_hexstr(key, [':', '-'], 16)


def parse_eui64(eui64: str) -> typing.Optional[bytes]:
    return parse_hexstr(eui64, [':', '-'], 8)


def parse_ipv6(addr: str) -> typing.Optional[ipaddress.IPv6Address]:
    try:
        return ipaddress.IPv6Address(addr)
    except ipaddress.AddressValueError:
        return None


def parse_int(val) -> typing.Optional[int]:
    try:
        return int(val)
    except ValueError:
        return None


def resolve_refs(obj):
    '''
    Resolve '$ref' in JSON objects (only 1 depth level).
    See https://swagger.io/docs/specification/using-ref/
    '''
    def _resolve_refs(subobj):
        if isinstance(subobj, list):
            for e in subobj:
                _resolve_refs(e)
        elif isinstance(subobj, dict):
            for v in subobj.values():
                _resolve_refs(v)
            if '$ref' in subobj:
                refkey = subobj.pop('$ref')
                assert refkey.startswith('#/')
                ref = obj
                for subkey in refkey.split('/')[1:]:
                    ref = ref[subkey]
                subobj |= ref # ref must be a dict
    obj = obj.copy()
    _resolve_refs(obj)
    return obj


def ctz(val):
    return int(val & -val).bit_length() - 1


def field_prep(mask, val):
    return (val << ctz(mask)) & mask


def field_max(mask):
    return mask >> ctz(mask)

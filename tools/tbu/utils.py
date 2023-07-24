import ipaddress
import socket


def fatal(msg):
    print(f'\x1b[31mfatal: {msg}\x1b[0m')
    exit(1)


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


def parse_key(key: str) -> bytes:
    if not isinstance(key, str):
        return None
    key = key.replace(':', '')
    if len(key) != 32:
        return None
    try:
        return bytes(int(key[i:i+2], 16) for i in range(0, 32, 2))
    except ValueError:
        return None


def parse_ipv6(addr: str) -> ipaddress.IPv6Address:
    try:
        return ipaddress.IPv6Address(addr)
    except ipaddress.AddressValueError:
        return None


def parse_int(val):
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

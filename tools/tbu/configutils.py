import configparser
import dataclasses
import ipaddress

import utils


@dataclasses.dataclass
class WstbuConfig:
    wstbu_port:    int
    uart_device:   str
    ipv6_prefix:   ipaddress.IPv6Network
    fan_version:   str
    radius_server: ipaddress.IPv6Address = None
    radius_secret: str = None
    dhcpv6_server: ipaddress.IPv6Address = None

    @property
    def tun_device(self):
        return 'tunwstbu'
    @property
    def tmp_dir(self):
        return f'/tmp/wstbu'
    @property
    def nvm_dir(self):
        return f'{self.tmp_dir}/nvm/'
    @property
    def fifo_path(self):
        return f'{self.tmp_dir}/fifo.pcap'


def read_wstbu(filename: str) -> dict:
    KW = [
        'wstbu_port',
        'uart_device',
        'ipv6_prefix',
        'fan_version',
    ]
    KW_OPT = [
        'radius_server',
        'radius_secret',
        'dhcpv6_server',
    ]

    try:
        cfg = configparser.ConfigParser()
        with open(filename, 'r') as file:
            cfg.read_file(file)
        if 'DEFAULT' not in cfg:
            utils.fatal(f'load config {filename}: missing section DEFAULT')
        if invalid_sct := next(filter(lambda x: x != 'DEFAULT', cfg), None):
            utils.fatal(f'load config {filename}: invalid section {invalid_sct}')
        cfg = cfg['DEFAULT']
        if missing_param := next(filter(lambda x: x not in cfg, KW), None):
            utils.fatal(f'load config {filename}: missing parameter {missing_param}')
        if invalid_param := next(filter(lambda x: x not in KW + KW_OPT, cfg), None):
            utils.fatal(f'load config {filename}: invalid parameter {invalid_param}')
        return WstbuConfig(**cfg)
    except Exception as e:
        utils.fatal(f'load config {filename}: {e}')


def write(filepath: str, **kwargs):
    '''Write config from dict in the form `key = val`'''
    with open(filepath, 'w') as file:
        for key, value in kwargs.items():
            # allowed_mac64 requires special handling
            if isinstance(value, list):
                for elem in value:
                    file.write(f'{key} = {elem}\n')
            else:
                file.write(f'{key} = {value}\n')

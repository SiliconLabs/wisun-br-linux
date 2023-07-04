import configparser
import dataclasses
import ipaddress

import utils


@dataclasses.dataclass
class WstbuConfig:
    wstbu_port:    int
    uart_device:   str
    ipv6_prefix:   ipaddress.IPv6Network
    radius_server: ipaddress.IPv6Address
    radius_secret: str
    dhcpv6_server: ipaddress.IPv6Address

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
    KEYWORDS = [
        'wstbu_port',
        'uart_device',
        'ipv6_prefix',
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
        if missing_param := next(filter(lambda x: x not in cfg, KEYWORDS), None):
            utils.fatal(f'load config {filename}: missing parameter {missing_param}')
        if invalid_param := next(filter(lambda x: x not in KEYWORDS, cfg), None):
            utils.fatal(f'load config {filename}: invalid parameter {invalid_param}')
        return WstbuConfig(**cfg)
    except Exception as e:
        utils.fatal(f'load config {filename}: {e}')


def write(filepath: str, config: dict):
    '''Write config from dict in the form `key = val`'''
    with open(filepath, 'w') as file:
        for key, value in config.items():
            # allowed_mac64 requires special handling
            if isinstance(value, list):
                for elem in value:
                    file.write(f'{key} = {elem}\n')
            else:
                file.write(f'{key} = {value}\n')

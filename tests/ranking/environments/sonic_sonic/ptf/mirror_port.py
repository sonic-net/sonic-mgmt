#!/usr/bin/env python3
"""Configure the current PTF SONiC ports to mirror ingress traffic to CPU0."""

import argparse
from pathlib import Path
import re
import subprocess


PORT_NAME = re.compile(r'Ethernet[0-9]+(?:_[0-9]+)?\Z')


def load_port_names(path):
    """Return validated SONiC interface names in physical wiring order."""
    names = []
    for number, raw in enumerate(Path(path).read_text(encoding='utf-8').splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        name = line.split()[0]
        if PORT_NAME.fullmatch(name) is None:
            raise ValueError('invalid SONiC port name at line {}: {!r}'.format(number, name))
        if name in names:
            raise ValueError('duplicate SONiC port name: {}'.format(name))
        names.append(name)
    if not names:
        raise ValueError('port config contains no SONiC ports')
    return names


def sdk_port_map(names):
    """Map wiring order to the verified TD5 SDK cd0..cd31 order."""
    if not isinstance(names, list) or not names:
        raise ValueError('port names must be a non-empty list')
    if len(names) != len(set(names)):
        raise ValueError('duplicate SONiC port name')
    for name in names:
        if not isinstance(name, str) or PORT_NAME.fullmatch(name) is None:
            raise ValueError('invalid SONiC port name: {!r}'.format(name))
    return {name: 'cd{}'.format(index) for index, name in enumerate(names)}


def apply_mirror(mode, port_config, container='syncd', runner=subprocess.run):
    """Apply one checked SDK command per configured PTF interface."""
    if mode != 'ingress':
        raise ValueError('only ingress mirror mode is supported')
    if not isinstance(container, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', container):
        raise ValueError('invalid sync container name')
    mapping = sdk_port_map(load_port_names(port_config))
    for sdk_port in mapping.values():
        command = 'mirror port {} mode=ingress dp=cpu0'.format(sdk_port)
        runner(['docker', 'exec', container, 'bcmcmd', '-c', command], check=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('ingress',))
    parser.add_argument('--port-config', required=True)
    parser.add_argument('--container', default='syncd')
    arguments = parser.parse_args(argv)
    apply_mirror(arguments.mode, arguments.port_config, arguments.container)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

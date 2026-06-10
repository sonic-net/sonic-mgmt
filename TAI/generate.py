"""
TAI adapter generator.

Creates a new platform adapter directory and patches factory.py and
platforms/__init__.py so the adapter is immediately usable.

Usage:
    # First of a family (inherits core base)
    python TAI/generate.py th7 --family tomahawk --parent core --hwsku <hwsku-prefix>

    # Sub-generation (inherits previous gen)
    python TAI/generate.py th7c --family tomahawk --parent th7 --hwsku <hwsku-prefix>

    # New family
    python TAI/generate.py q5d --family qumran2 --parent core --hwsku <hwsku-prefix>
"""

import argparse
import os
import re
import sys
import textwrap

TAI_DIR = os.path.dirname(os.path.abspath(__file__))
PLATFORMS_DIR = os.path.join(TAI_DIR, 'platforms')
FACTORY_PATH = os.path.join(TAI_DIR, 'core', 'factory.py')
PLATFORMS_INIT = os.path.join(PLATFORMS_DIR, '__init__.py')


def class_name(identifier: str) -> str:
    """'th6' → 'TH6', 'q3d' → 'Q3D'"""
    return identifier.upper()


def all_thrift_features() -> str:
    """Return the full supported_features set used by base Tomahawk adapters."""
    return textwrap.dedent("""\
        supported_features = {
            'get_pg_counters',
            'get_pg_drop_counters',
            'get_pg_all_drop_counters',
            'get_pg_pkts_received',
            'get_pkts_num_leak_out',
            'compensate_leakout',
            'get_port_counters',
            'get_ingress_drop_margin',
            'get_active_ingress_drop_counters',
            'tx_disable',
            'tx_enable',
            'send_pkts_short_of_pfc',
            'check_rx_drop',
            'check_tx_drop',
            'check_pfc_triggered',
        }""")


def all_qos_features() -> str:
    return textwrap.dedent("""\
        supported_features = {
            'discover_queue_key',
            'create_scheduler',
            'apply_scheduler',
            'get_interface_drop_count',
            'get_pg_profile',
            'create_or_update_pg_profile',
            'apply_pg_profile',
            'delete_pg_profile',
        }""")


def generate_thrift(name: str, family: str, parent: str) -> str:
    cls = class_name(name)
    if parent == 'core':
        return textwrap.dedent(f'''\
            """
            {cls} ThriftAdapter.
            """

            import logging

            from TAI.core.thrift import ThriftAdapter
            from TAI.core.factory import AdapterFactory

            logger = logging.getLogger(__name__)


            @AdapterFactory.register(ThriftAdapter, {name!r})
            class {cls}ThriftAdapter(ThriftAdapter):
                platform_name = {name!r}

                {all_thrift_features()}

                # TODO: override methods that differ from base ThriftAdapter
            ''')  # noqa: E272,E231
    else:
        parent_cls = class_name(parent)
        return textwrap.dedent(f'''\
            """
            {cls} ThriftAdapter — inherits {parent_cls}, overrides what diverges.
            """

            import logging

            from TAI.core.thrift import ThriftAdapter
            from TAI.core.factory import AdapterFactory
            from TAI.platforms.{family}.{parent}.thrift import {parent_cls}ThriftAdapter

            logger = logging.getLogger(__name__)


            @AdapterFactory.register(ThriftAdapter, {name!r})
            class {cls}ThriftAdapter({parent_cls}ThriftAdapter):
                platform_name = {name!r}
                # Inherits all {parent_cls} behaviour — add overrides here
            ''')  # noqa: E272,E231


def generate_qos(name: str, family: str, parent: str) -> str:
    cls = class_name(name)
    if parent == 'core':
        return textwrap.dedent(f'''\
            """
            {cls} QoSAdapter.
            """

            import logging
            from typing import Optional

            from TAI.core.qos import QoSAdapter
            from TAI.core.factory import AdapterFactory

            logger = logging.getLogger(__name__)


            @AdapterFactory.register(QoSAdapter, {name!r})
            class {cls}QoSAdapter(QoSAdapter):
                platform_name = {name!r}

                {all_qos_features()}

                # TODO: override methods that differ from base QoSAdapter
            ''')  # noqa: E272,E231
    else:
        parent_cls = class_name(parent)
        return textwrap.dedent(f'''\
            """
            {cls} QoSAdapter — inherits {parent_cls}, overrides what diverges.
            """

            import logging

            from TAI.core.qos import QoSAdapter
            from TAI.core.factory import AdapterFactory
            from TAI.platforms.{family}.{parent}.qos import {parent_cls}QoSAdapter

            logger = logging.getLogger(__name__)


            @AdapterFactory.register(QoSAdapter, {name!r})
            class {cls}QoSAdapter({parent_cls}QoSAdapter):
                platform_name = {name!r}
                # Inherits all {parent_cls} behaviour — add overrides here
            ''')  # noqa: E272,E231


def generate_adapter_init(name: str) -> str:
    cls = class_name(name)
    qos_cls = f'{cls}QoSAdapter'
    thrift_cls = f'{cls}ThriftAdapter'
    return textwrap.dedent(f'''\
        from .qos import {qos_cls}
        from .thrift import {thrift_cls}

        __all__ = ['{qos_cls}', '{thrift_cls}']
        ''')  # noqa: E272


def patch_factory(name: str, hwsku: str) -> None:
    with open(FACTORY_PATH) as f:
        src = f.read()

    if f"'{hwsku}'" in src:
        return

    src = re.sub(
        r'(_hwsku_prefix_map\s*=\s*\[)',
        rf"\1\n        ({hwsku!r}, {name!r}),",  # noqa: E231
        src,
    )

    with open(FACTORY_PATH, 'w') as f:
        f.write(src)


def patch_family_init(family_dir: str, name: str) -> None:
    init_path = os.path.join(family_dir, '__init__.py')
    if os.path.exists(init_path):
        with open(init_path) as f:
            src = f.read()
        if f'import {name}' not in src:
            src = re.sub(r'(__all__\s*=\s*\[)', rf'\1\n    {name!r},', src)  # noqa: E231
            src = src.rstrip('\n') + f'\nfrom . import {name}\n'
        with open(init_path, 'w') as f:
            f.write(src)
    else:
        with open(init_path, 'w') as f:
            f.write(f'from . import {name}\n\n__all__ = [{name!r}]\n')


def patch_platforms_init(family: str) -> None:
    with open(PLATFORMS_INIT) as f:
        src = f.read()
    if f'import {family}' not in src:
        src = re.sub(r'(__all__\s*=\s*\[)', rf'\1\n    {family!r},', src)  # noqa: E231
        src = src.rstrip('\n') + f'\nfrom . import {family}\n'
        with open(PLATFORMS_INIT, 'w') as f:
            f.write(src)


def main():
    parser = argparse.ArgumentParser(description='Generate a new TAI platform adapter.')
    parser.add_argument('name', help='ASIC identifier (e.g. th7, q5d)')
    parser.add_argument('--family', required=True, help='Family folder (e.g. tomahawk, qumran)')
    parser.add_argument('--parent', required=True,
                        help='Parent adapter name or "core" for base ThriftAdapter/QoSAdapter')
    parser.add_argument('--hwsku', required=True,
                        help='hwsku prefix used by the factory to detect this platform')
    args = parser.parse_args()

    name = args.name
    family = args.family
    parent = args.parent
    hwsku = args.hwsku

    adapter_dir = os.path.join(PLATFORMS_DIR, family, name)
    if os.path.exists(adapter_dir):
        print(f'ERROR: {adapter_dir} already exists', file=sys.stderr)
        sys.exit(1)

    os.makedirs(adapter_dir)
    with open(os.path.join(adapter_dir, '__init__.py'), 'w') as f:
        f.write(generate_adapter_init(name))
    with open(os.path.join(adapter_dir, 'thrift.py'), 'w') as f:
        f.write(generate_thrift(name, family, parent))
    with open(os.path.join(adapter_dir, 'qos.py'), 'w') as f:
        f.write(generate_qos(name, family, parent))

    print(f'Created {adapter_dir}/')

    family_dir = os.path.join(PLATFORMS_DIR, family)
    patch_family_init(family_dir, name)
    print(f'Patched  TAI/platforms/{family}/__init__.py')

    patch_platforms_init(family)
    print('Patched  TAI/platforms/__init__.py')

    patch_factory(name, hwsku)
    print('Patched  TAI/core/factory.py')
    print(f'         _hwsku_prefix_map += ({hwsku!r}, {name!r})')


if __name__ == '__main__':
    main()

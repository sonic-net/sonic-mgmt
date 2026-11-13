from pathlib import Path

import pytest

from tests.ranking.cases.tools.generate_manifest import build_manifest


@pytest.fixture
def manifest():
    return build_manifest(
        ['sairoute.RouteA', 'saivlan.VlanA', 'sairoute.RouteB'],
        {'repo': 'SAI', 'commit': 'a' * 40},
        {},
    )


def load_port_config(path):
    """Read checked-in port fixtures for comparison with environment data."""
    header = None
    ports = {}
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        columns = line.strip().lstrip('#').split()
        if not columns:
            continue
        if line.lstrip().startswith('#'):
            if columns[0] == 'name':
                assert header is None and len(columns) == len(set(columns))
                header = columns
            continue
        assert header is not None and len(columns) == len(header)
        row = dict(zip(header, columns))
        name = row.pop('name')
        assert name not in ports
        row['lanes'] = [int(lane) for lane in row['lanes'].split(',')]
        ports[name] = row
    assert ports
    return ports

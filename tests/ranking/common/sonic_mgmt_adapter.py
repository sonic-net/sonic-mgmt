"""Materialize private standard sonic-mgmt inputs for one Ranking process."""

from dataclasses import dataclass
from copy import deepcopy
import os
from pathlib import Path
import shutil
import tempfile

import yaml


@dataclass(frozen=True)
class ControllerAdapter:
    root: Path
    inventory: Path
    testbed_file: Path
    testbed: str
    host_pattern: str

    def cleanup(self):
        shutil.rmtree(str(self.root))


def _private_yaml(path, value):
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as sink:
            yaml.safe_dump(value, sink, sort_keys=False)
            sink.flush()
            os.fsync(sink.fileno())
    except BaseException:
        if path.exists():
            path.unlink()
        raise


def _private_copy(source, destination):
    data = source.read_bytes()
    descriptor = os.open(
        str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as sink:
            sink.write(data)
            sink.flush()
            os.fsync(sink.fileno())
    except BaseException:
        if destination.exists():
            destination.unlink()
        raise


def create_controller_adapter(spec, temp_parent=None):
    """Create a mode-0700 directory containing mode-0600 adapter files."""
    root = Path(tempfile.mkdtemp(prefix='ranking-controller-', dir=temp_parent))
    os.chmod(str(root), 0o700)
    inventory = root / 'inventory.yml'
    adapter_ansible = root / 'ansible'
    adapter_vars = adapter_ansible / 'vars'
    adapter_vars.mkdir(parents=True, mode=0o700)
    os.chmod(str(adapter_ansible), 0o700)
    os.chmod(str(adapter_vars), 0o700)
    testbed_file = adapter_ansible / 'testbed.yaml'
    try:
        inventory_value = deepcopy(spec['inventory'])
        testbed_entry = deepcopy(spec['testbed_entry'])
        topology_source = Path(spec['topology_source']).resolve()
        testbed = spec['testbed_name']
        host_pattern = spec['host_pattern']
    except (KeyError, TypeError) as error:
        shutil.rmtree(str(root), ignore_errors=True)
        raise ValueError('controller adapter spec is incomplete') from error
    if (not isinstance(inventory_value, dict) or not isinstance(testbed_entry, dict)
            or not isinstance(testbed, str) or not testbed
            or not isinstance(host_pattern, str) or not host_pattern):
        shutil.rmtree(str(root), ignore_errors=True)
        raise ValueError('controller adapter spec is incomplete')
    topology_file = adapter_vars / topology_source.name
    if 'inv_name' in testbed_entry:
        shutil.rmtree(str(root), ignore_errors=True)
        raise ValueError('controller adapter owns testbed inv_name')
    testbed_entry['inv_name'] = str(inventory)
    testbed_value = [testbed_entry]
    try:
        if not topology_source.is_file():
            raise ValueError(
                'standard sonic-mgmt topology is missing: {}'.format(topology_source))
        _private_copy(topology_source, topology_file)
        _private_yaml(inventory, inventory_value)
        _private_yaml(testbed_file, testbed_value)
    except BaseException:
        shutil.rmtree(str(root), ignore_errors=True)
        raise
    return ControllerAdapter(
        root=root, inventory=inventory, testbed_file=testbed_file,
        testbed=testbed, host_pattern=host_pattern)


def explicit_standard_options(config):
    """Return standard sonic-mgmt controller inputs explicitly set by a caller."""
    arguments = tuple(str(value) for value in getattr(
        getattr(config, 'invocation_params', None), 'args', ()))
    names = ('--inventory', '-i', '--testbed', '--testbed_file',
             '--host-pattern', '--ansible-host-pattern')
    return [
        name for name in names
        if any(argument == name or argument.startswith(name + '=')
               or (name == '-i' and argument.startswith('-i')
                   and argument != '-i')
               for argument in arguments)
    ]

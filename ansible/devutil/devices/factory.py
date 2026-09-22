import json
import logging
import os
import sys
import yaml

from .ansible_hosts import AnsibleHost
from .ansible_hosts import AnsibleHosts
from .ansible_hosts import NoAnsibleHostError
from .ansible_hosts import MultipleAnsibleHostsError
from .sonic import SonicHosts

logger = logging.getLogger(__name__)

_self_dir = os.path.dirname(os.path.abspath(__file__))
ansible_path = os.path.realpath(os.path.join(_self_dir, "../../"))


def _resolve_localhost_python_interpreter():
    """Return a python interpreter that has the sonic-mgmt dependencies
    (PyYAML, ansible, etc.) available.

    Historically this was hardcoded to ``/usr/bin/python3``. That assumes the
    sonic-mgmt docker image installs every dependency into system python,
    which is no longer true: the new ``docker-sonic-mgmt`` image installs
    everything into a uv-managed venv at ``/opt/venv`` and leaves
    ``/usr/bin/python3`` bare. Calling Ansible modules on localhost via the
    bare system python then fails with
    ``ModuleNotFoundError: No module named 'yaml'``.

    Resolution order:
      1. ``LOCALHOST_PYTHON_INTERPRETER`` env override.
      2. ``sys.executable`` -- the interpreter actually running this code,
         which by definition has our deps.
      3. ``/usr/bin/python3`` legacy fallback.
    """
    override = os.environ.get("LOCALHOST_PYTHON_INTERPRETER")
    if override:
        return override
    if sys.executable and os.path.exists(sys.executable):
        return sys.executable
    return "/usr/bin/python3"


def init_localhost(inventories=None, options={}, hostvars={}):
    try:
        ah = AnsibleHost(inventories, "localhost", options=options.copy(), hostvars=hostvars.copy())
    except (NoAnsibleHostError, MultipleAnsibleHostsError) as e:
        logger.error(
            "Failed to initialize localhost from inventories '{}', exception: {}".format(str(inventories), repr(e))
        )
        return None

    # Pin ansible_python_interpreter for localhost only, by setting it as a
    # host-level variable on the inventory Host object.
    #
    # We deliberately do NOT pass this through the ``hostvars`` kwarg of
    # AnsibleHost: that path lands in ``VariableManager.extra_vars`` (see
    # ``AnsibleHostsBase.__init__``), and ansible-core's
    # ``ansible.utils.vars.load_extra_vars`` caches its return dict on the
    # function object. Every VariableManager constructed afterwards in the
    # same process shares the same ``_extra_vars`` dict, so a mutation here
    # would leak ``ansible_python_interpreter`` to every subsequent play --
    # including ones targeting real DUTs that do not have the controller's
    # interpreter path. extra_vars also have the highest precedence in
    # ansible, so they would override the DUTs' inventory/group vars.
    interpreter = _resolve_localhost_python_interpreter()
    try:
        for h in ah.im.get_hosts("localhost"):
            h.set_variable("ansible_python_interpreter", interpreter)
    except Exception as e:
        logger.warning(
            "Failed to pin ansible_python_interpreter='{}' on localhost: {}".format(interpreter, repr(e))
        )

    return ah


def init_host(inventories, host_pattern, options={}, hostvars={}):
    try:
        return AnsibleHost(inventories, host_pattern, options=options.copy(), hostvars=hostvars.copy())
    except NoAnsibleHostError as e:
        logger.error(
            "No host '{}' in inventories '{}', exception: {}".format(host_pattern, inventories, repr(e))
        )
        return None
    except MultipleAnsibleHostsError as e:
        logger.error(
            "Multiple hosts '{}' in inventories '{}', exception: {}".format(host_pattern, inventories, repr(e))
        )
        return None


def init_hosts(inventories, host_pattern, options={}, hostvars={}):
    try:
        return AnsibleHosts(inventories, host_pattern, options=options.copy(), hostvars=hostvars.copy())
    except NoAnsibleHostError as e:
        logger.error(
            "No hosts '{}' in inventories '{}', exception: {}".format(host_pattern, inventories, repr(e))
        )
        return None


def init_sonichosts(inventories, host_pattern, options={}, hostvars={}):
    try:
        return SonicHosts(inventories, host_pattern, options=options.copy(), hostvars=hostvars.copy())
    except NoAnsibleHostError as e:
        logger.error(
            "No hosts '{}' in inventories '{}', exception: {}".format(host_pattern, inventories, repr(e))
        )
        return None


def init_testbed_sonichosts(inventories, testbed_name, testbed_file="testbed.yaml", options={}, hostvars={}):
    testbed_file_path = os.path.join(ansible_path, testbed_file)
    with open(testbed_file_path) as f:
        testbeds = yaml.safe_load(f.read())

    duts = None
    for testbed in testbeds:
        if testbed["conf-name"] == testbed_name:
            duts = testbed["dut"]   # Type is list, historic reason.
            break

    if not duts:
        logger.error("No testbed with name '{}' in testbed file {}".format(testbed_name, testbed_file_path))
        return None

    sonichosts = init_sonichosts(inventories, duts, options=options.copy(), hostvars=hostvars.copy())
    if sonichosts and sonichosts.hosts_count != len(duts):
        logger.error(
            "Unmatched testbed duts: '{}', inventory: '{}', found hostnames: '{}'".format(
                json.dumps(duts),
                inventories,
                json.dumps(sonichosts.hostnames)
            )
        )
        return None

    return sonichosts

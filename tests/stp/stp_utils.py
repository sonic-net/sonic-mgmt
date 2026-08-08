"""
Mode-aware STP DB/verify helpers shared by the PVST and MSTP tests.

Every helper takes `mode` ("pvst" | "mst") and a `scope` so a single call site
works for both protocols:

  * PVST scope is the VLAN id   -> APPL_DB `_STP_VLAN_TABLE:Vlan<vid>` /
                                   `_STP_VLAN_PORT_TABLE:Vlan<vid>:<port>`
  * MST  scope is the instance  -> APPL_DB `_STP_MST_INST_TABLE:<inst>` /
                                   `_STP_MST_PORT_TABLE:<inst>:<port>`

The stp daemon writes these via a ProducerStateTable with no consumer, so on
hardware they live under the `_`-prefixed temp keys (APPL_DB, db 0).
"""
import logging

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

PVST = "pvst"
MST = "mst"


def _hgetall(duthost, key, dbnum=0):
    """HGETALL a redis key into a dict (empty dict if absent)."""
    cmd = "redis-cli -n {} HGETALL '{}'".format(dbnum, key)
    out = duthost.shell(cmd, module_ignore_errors=True).get("stdout_lines", [])
    return dict(zip(out[::2], out[1::2]))


def bridge_key(mode, scope):
    if mode == MST:
        return "_STP_MST_INST_TABLE:{}".format(scope)
    return "_STP_VLAN_TABLE:Vlan{}".format(scope)


def port_key(mode, scope, port):
    if mode == MST:
        return "_STP_MST_PORT_TABLE:{}:{}".format(scope, port)
    return "_STP_VLAN_PORT_TABLE:Vlan{}:{}".format(scope, port)


def get_bridge_data(duthost, mode, scope):
    """Per-VLAN (PVST) / per-instance (MST) bridge state, as a dict."""
    return _hgetall(duthost, bridge_key(mode, scope))


def get_port_data(duthost, mode, scope, port):
    """Per-port state, as a dict."""
    return _hgetall(duthost, port_key(mode, scope, port))


def get_port_state(duthost, mode, scope, port):
    data = get_port_data(duthost, mode, scope, port)
    state = data.get("port_state")
    pytest_assert(state, "port_state not found in {}".format(port_key(mode, scope, port)))
    return state


def get_port_cost(duthost, mode, scope, port):
    data = get_port_data(duthost, mode, scope, port)
    return int(data.get("path_cost", "0"))


def get_root_port(duthost, mode, scope):
    data = get_bridge_data(duthost, mode, scope)
    root_port = data.get("root_port")
    pytest_assert(root_port, "root_port not found in {}".format(bridge_key(mode, scope)))
    return root_port


def is_self_root(duthost, mode, scope):
    """True when the DUT is the (regional, for MST) root for this scope.

    The daemon signals "this bridge is the root" by writing `root_port` as the
    literal string ``Root``. (The address fields can't be compared directly: on
    MST the daemon zeroes the priority nibble of `bridge_address` while keeping
    it on `root_address`, so they never compare equal even when self-root.)
    """
    data = get_bridge_data(duthost, mode, scope)
    return data.get("root_port") == "Root"


def verify_stp_state(duthost, mode, scope, ports, expected_state, timeout=120, interval=2):
    """Wait for `ports` to reach `expected_state`, asserting on timeout."""
    for port in ports:
        ok = wait_until(
            timeout, interval, 0,
            lambda p=port: get_port_data(duthost, mode, scope, p).get("port_state") == expected_state
        )
        cur = get_port_data(duthost, mode, scope, port).get("port_state")
        pytest_assert(ok, "{} did not reach {} within {}s (current: {})".format(
            port, expected_state, timeout, cur))


# --- MST-only ---------------------------------------------------------------
def get_mst_boundary(duthost, port):
    """`_STP_PORT_TABLE:<port>.mst_boundary` (yes/no), instance-independent."""
    return _hgetall(duthost, "_STP_PORT_TABLE:{}".format(port)).get("mst_boundary")


def get_mst_instances(duthost):
    """List of configured MST instance ids present in APPL_DB."""
    out = duthost.shell("redis-cli -n 0 keys '_STP_MST_INST_TABLE:*'",
                        module_ignore_errors=True).get("stdout_lines", [])
    return sorted(int(k.split(":")[-1]) for k in out if k.strip())


def get_instance_vlans(duthost, instance):
    """VLANs mapped to an MST instance (from `_STP_MST_INST_TABLE:<inst>.vlan@`)."""
    raw = get_bridge_data(duthost, MST, instance).get("vlan@", "")
    return [int(v) for v in raw.split(",") if v.strip()]


# --- mode-independent port helpers (unchanged from pvst_utils) ---------------
def get_port_oper_state(duthost, port):
    return duthost.shell("redis-cli -n 0 HGET PORT_TABLE:{} oper_status".format(port),
                         module_ignore_errors=True).get("stdout", "").strip()


def get_port_admin_state(duthost, port):
    return duthost.shell("redis-cli -n 0 HGET PORT_TABLE:{} admin_status".format(port),
                         module_ignore_errors=True).get("stdout", "").strip()


def fdb_has_mac_for_interface(duthost, interface, mac_prefix=""):
    res = duthost.command('fdbshow')
    for line in res['stdout_lines']:
        if interface in line and (mac_prefix in line or mac_prefix == ""):
            return True
    return False

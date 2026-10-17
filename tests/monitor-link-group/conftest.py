"""Fixtures for monitor-link-group tests.

The `intf_pool` fixture is module-scoped (matching the scope of
`rand_one_dut_hostname`): it discovers operationally-up Ethernet
interfaces and PortChannels from the DUT once per module. The `mlg`
fixture is function-scoped and guarantees per-test cleanup -- any
groups it created are deleted and any interfaces it shut are restored.
"""

import logging

import pytest

import monitor_link_helpers as mlg_helpers

logger = logging.getLogger(__name__)


class InterfacePool:
    """Simple oper-up Ethernet + PortChannel pool with allocate/release.

    Discovers interfaces from `duthost.get_interfaces_status()` and
    filters to oper=up. Does NOT bring up admin-down interfaces.
    Tests skip when not enough interfaces are available.
    """

    def __init__(self, duthost):
        self.duthost = duthost
        status = duthost.get_interfaces_status()

        self._eth = sorted(
            [n for n, s in status.items()
             if n.startswith("Ethernet") and s.get("oper") == "up"],
            key=_eth_sort_key,
        )
        self._pc = sorted(
            [n for n, s in status.items()
             if n.startswith("PortChannel") and s.get("oper") == "up"],
            key=_pc_sort_key,
        )
        self._allocated_eth = set()
        self._allocated_pc = set()
        logger.info("InterfacePool: %d Ethernet, %d PortChannel",
                    len(self._eth), len(self._pc))

    def available(self):
        return [i for i in self._eth if i not in self._allocated_eth]

    def available_portchannels(self):
        return [pc for pc in self._pc if pc not in self._allocated_pc]

    def allocate(self, count):
        avail = self.available()
        if len(avail) < count:
            raise ValueError(
                "Not enough Ethernet interfaces: requested {}, available {}".format(
                    count, len(avail)))
        chosen = avail[:count]
        self._allocated_eth.update(chosen)
        return chosen

    def allocate_portchannels(self, count):
        avail = self.available_portchannels()
        if len(avail) < count:
            raise ValueError(
                "Not enough PortChannels: requested {}, available {}".format(
                    count, len(avail)))
        chosen = avail[:count]
        self._allocated_pc.update(chosen)
        return chosen

    def release(self, *interfaces):
        # Drop interfaces that ended the test oper-down from the pool so
        # the next test does not pick them up.
        status = self.duthost.get_interfaces_status()
        for intf in interfaces:
            if intf.startswith("PortChannel"):
                self._allocated_pc.discard(intf)
                if status.get(intf, {}).get("oper") != "up":
                    self._pc = [pc for pc in self._pc if pc != intf]
            else:
                self._allocated_eth.discard(intf)
                if status.get(intf, {}).get("oper") != "up":
                    self._eth = [e for e in self._eth if e != intf]


def _eth_sort_key(name):
    try:
        return int(name.replace("Ethernet", ""))
    except ValueError:
        return name


def _pc_sort_key(name):
    try:
        return int(name.replace("PortChannel", ""))
    except ValueError:
        return name


@pytest.fixture(scope="module", autouse=True)
def _skip_if_mlg_daemon_absent(duthosts, rand_one_dut_hostname):
    """Skip the whole module if monitorlinkgroupd is not present on the DUT.

    The MLG sonic-mgmt tests depend on the monitorlinkgroupd daemon (added
    by sonic-net/sonic-swss#4523). When run against an older image that
    does not yet ship the daemon, CONFIG_DB writes succeed but no
    STATE_DB row is ever populated, which would otherwise surface as a
    confusing wait_group_state timeout on the first scenario. Skipping
    keeps the suite safe to land ahead of the swss merge and the
    corresponding KVM image refresh.
    """
    duthost = duthosts[rand_one_dut_hostname]
    if not mlg_helpers.is_mlg_daemon_present(duthost):
        pytest.skip(
            "monitorlinkgroupd not present on DUT image; skipping "
            "monitor-link-group tests"
        )


@pytest.fixture(scope="module")
def intf_pool(duthosts, rand_one_dut_hostname):
    return InterfacePool(duthosts[rand_one_dut_hostname])


class MlgContext:
    """Tracks resources created during a single test for cleanup."""

    def __init__(self, duthost, intf_pool):
        self.duthost = duthost
        self.pool = intf_pool
        self._groups = []
        self._shutdown_intfs = set()
        self._allocated = []

    def allocate(self, count):
        intfs = self.pool.allocate(count)
        self._allocated.extend(intfs)
        return intfs

    def allocate_portchannels(self, count):
        pcs = self.pool.allocate_portchannels(count)
        self._allocated.extend(pcs)
        return pcs

    def apply(self, groups):
        for name in groups:
            if name not in self._groups:
                self._groups.append(name)
        mlg_helpers.apply_groups(self.duthost, groups)

    def delete_group(self, name):
        mlg_helpers.delete_group(self.duthost, name)
        if name in self._groups:
            self._groups.remove(name)

    def shutdown(self, intf):
        self._shutdown_intfs.add(intf)
        mlg_helpers.shutdown(self.duthost, intf)

    def no_shutdown(self, intf):
        mlg_helpers.no_shutdown(self.duthost, intf)
        self._shutdown_intfs.discard(intf)

    def cleanup(self):
        for name in list(self._groups):
            mlg_helpers.delete_group(self.duthost, name)
        self._groups.clear()
        for intf in list(self._shutdown_intfs):
            try:
                mlg_helpers.no_shutdown(self.duthost, intf)
            except Exception:
                logger.exception("failed to restore admin-up on %s", intf)
        # Wait for restored interfaces to actually return to oper-up
        # before releasing; InterfacePool.release() purges interfaces
        # that are not oper-up so the pool stays trustworthy.
        for intf in list(self._shutdown_intfs):
            try:
                mlg_helpers.wait_oper(self.duthost, intf, "up", timeout=30)
            except AssertionError:
                logger.warning("interface %s did not return to oper-up; "
                               "it will be dropped from the pool", intf)
        self._shutdown_intfs.clear()
        if self._allocated:
            self.pool.release(*self._allocated)
        self._allocated.clear()


@pytest.fixture
def mlg(duthosts, rand_one_dut_hostname, intf_pool):
    duthost = duthosts[rand_one_dut_hostname]
    ctx = MlgContext(duthost, intf_pool)
    yield ctx
    ctx.cleanup()

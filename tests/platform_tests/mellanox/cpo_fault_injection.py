"""CPO fault injection via the PMFT access register.

Fault injection goes through ``mlxreg --reg_name PMFT``, which works the
same on SIMX and on physical ASICs, so it is the single mechanism used here.

PMFT's register layout (verified with ``mlxreg --show_reg PMFT``) carries
exactly one writable fault selector::

    num_of_faults_to_trigger      | WO
    fault_type                    | WO
    time_interval_between_faults  | WO
    set_laser_source_fault        | WO
    laser_source_faults_cap       | RO
    module_type_cap               | RO
    cpo_module_faults_cap         | RO

There is therefore **no way to inject a module-level (thermal) fault**:
``cpo_module_faults_cap`` is read-only capability advertisement, not a
trigger. Every catalogued fault below is consequently ELS/laser scoped.

vModule topology (SN6810_LD):

    1 vModule = 4 banks (sub_modules) = 8 ELS lasers = 32 lanes
              = 8 logical ports (1x2 breakout, 4 lanes each)

    16 vModules x 32 lanes = 512 lanes = 128 CPO ports.

Each ELS laser serves **4 lanes**. Read off the
``oe_laneN_to_els_logical_laser`` map in
``/sys/module/sx_core/asic0/module<N>/module_cpo_info``, which assigns
logical lasers 0..7 across the four sub_modules::

    sub_module 0: lanes 0-3 -> laser 0,  lanes 4-7 -> laser 1
    sub_module 1: lanes 0-3 -> laser 2,  lanes 4-7 -> laser 3
    sub_module 2: lanes 0-3 -> laser 4,  lanes 4-7 -> laser 5
    sub_module 3: lanes 0-3 -> laser 6,  lanes 4-7 -> laser 7

Index conventions:

* ``module_index`` is the **ELS index** (0..15), *not* the SDK module
  index. One ELS spans the four banks above. It is also the index the
  kernel uses for
  ``/sys/module/sx_core/asic0/module<els_index>/interrupt``.
* ``lane_mask`` is, despite its name, an 8-bit **laser** mask -- one bit
  per ELS laser, ``1 << laser``. That is why 8 bits cover a 32-lane
  vModule. ``lane_mask=0`` selects no laser at all: ``mlxreg`` still
  reports success, but nothing is injected and no interrupt is raised.
* Tokens are named after the **one-based ELS logical laser**, so laser
  ``k`` reports ``..._lane{k+1}``. Verified: laser 0 -> ``lane1``,
  laser 3 -> ``lane4``, laser 4 -> ``lane5``. The token therefore covers
  the laser's four lanes, not one lane.
"""
import logging
import re

from tests.common.helpers.assertions import pytest_assert
from tests.platform_tests.mellanox.cpo_fault_helpers import clear_xcvr_fault

logger = logging.getLogger(__name__)

# PMFT module_index is the ELS index; one ELS drives BANKS_PER_VMODULE banks.
ELS_INDEX_MIN = 0

# PMFT set_laser_source_fault values:
#   1 APC, 2 TEC loop, 3 high power, 4 low power, 5 ramping timeout.
# PMFT fault_type: 0 alarm, 1 warning.
#
# The resulting STATE_DB token depends on BOTH fields, and the two
# fault_type values land in different token families:
#
#   fault_type=0 (alarm)   -> xcvr_cpo_els_<high|low>_power_alarm_laneN
#                             (decoded from the DOM/STATUS_FLAG path)
#   fault_type=1 (warning) -> xcvr_cpo_els_warning_code_laneN
#                             (decoded from pg1A:212-219 lane nibbles;
#                              the specific laser fault becomes the 4-bit
#                              *code* inside the line, not a distinct token)
#
# Each entry's ``token`` is a format string taking the one-based ELS
# logical laser number.
CPO_FAULTS = {
    "laser_high_power_alarm": {
        "token": "xcvr_cpo_els_high_power_alarm_lane{lane}",
        "scope": "lane",
        "fault_type": 0,
        "laser_source_fault": 3,
    },
    "laser_low_power_alarm": {
        "token": "xcvr_cpo_els_low_power_alarm_lane{lane}",
        "scope": "lane",
        "fault_type": 0,
        "laser_source_fault": 4,
    },
    "apc_failure_warning": {
        "token": "xcvr_cpo_els_warning_code_lane{lane}",
        "scope": "lane",
        "fault_type": 1,
        "laser_source_fault": 1,
        # 4-bit code carried inside the WARNING line: "(code 1, APC control loop)".
        "lane_code": 1,
    },
}

# Tokens name the ELS logical laser one-based, so laser k -> "..._lane{k+1}".
# Verified: laser 0 -> lane1, laser 3 -> lane4, laser 4 -> lane5.
TOKEN_LANE_OFFSET = 1

# ELS lasers per vModule (module_cpo_info: logical lasers 0..7).
LASERS_PER_VMODULE = 8
# Lanes each ELS laser serves.
LANES_PER_LASER = 4


def token_for(fault_key, laser):
    """Return the concrete STATE_DB token for ``fault_key`` at ``laser``."""
    pytest_assert(fault_key in CPO_FAULTS, "Unknown CPO fault '{}'".format(fault_key))
    return CPO_FAULTS[fault_key]["token"].format(lane=laser + TOKEN_LANE_OFFSET)


# Shape of the WARNING line the feature emits, from its format
# string ``"CPO fault: %s %s%s"`` (logical port, token, optional code
# suffix) logged via ``logger.log_warning``. Rendered by syslog, e.g.:
#
#   ... sonic WARNING pmon#xcvrd: CPO fault: Ethernet416 \
#       xcvr_cpo_els_warning_code_lane1 (code 1, APC control loop)
#
# Binding the severity, the emitting process and the port means a stray
# occurrence of the token elsewhere in syslog cannot satisfy the
# assertion. The trailing ``(?!\d)`` stops ``..._lane1`` from matching a
# ``..._lane10`` line -- harmless with today's eight lasers, but wrong
# the moment a platform exposes more.
SYSLOG_LINE_TEMPLATE = (
    r".*WARNING \S*pmon#xcvrd: CPO fault: {port} {token}(?!\d).*")


def syslog_regex_for(fault_key, laser, port):
    """Return the syslog regex for ``fault_key`` at ``laser`` on ``port``.

    Args:
        fault_key: key into ``CPO_FAULTS``.
        laser: zero-based ELS laser index.
        port: logical port the WARNING line must name.
    """
    return SYSLOG_LINE_TEMPLATE.format(
        port=re.escape(port), token=re.escape(token_for(fault_key, laser)))


class CpoFaultInjector(object):
    """Inject ELS laser faults into one zero-based ELS (vModule) index."""

    def __init__(self, duthost, els_index, logical_port, mst_dev=None):
        """
        Args:
            duthost: the DUT host object.
            els_index: zero-based **ELS index** (PMFT ``module_index``).
            logical_port: a logical port of that vModule, used for reset.
            mst_dev: optional explicit MST device path.
        """
        self.duthost = duthost
        self.els_index = els_index
        self.logical_port = logical_port
        self._mst_dev = mst_dev
        self._injected = []

    def _list_mst_cr_devices(self):
        result = self.duthost.shell(
            "ls /dev/mst/*_pci_cr* 2>/dev/null",
            module_ignore_errors=True,
        )
        return [line.strip() for line in result.get("stdout_lines", []) if line.strip()]

    def _resolve_mst_dev(self):
        if self._mst_dev:
            return self._mst_dev
        # PMFT is served by the cr0 (config-register) device, not pciconf.
        devices = self._list_mst_cr_devices()
        if not devices:
            # The image no longer runs `mst start` on boot, so /dev/mst may
            # not exist yet; load the MST driver and look again.
            logger.info("No MST cr device found, running 'mst start'")
            self.duthost.shell("sudo mst start", module_ignore_errors=True)
            devices = self._list_mst_cr_devices()
        pytest_assert(devices, "No MST cr device found for PMFT fault injection")
        # The suite is single-ASIC only, so exactly one cr device is expected.
        # Refuse to guess if there are more: picking by filesystem order could
        # inject into a device that does not serve the CPO ASIC.
        pytest_assert(
            len(devices) == 1,
            "Ambiguous MST cr devices for PMFT fault injection: {}; pass mst_dev "
            "explicitly".format(devices))
        self._mst_dev = devices[0]
        return self._mst_dev

    def _run_checked(self, cmd, description):
        logger.info("%s: %s", description, cmd)
        result = self.duthost.shell(cmd, module_ignore_errors=True)
        pytest_assert(
            result.get("rc") == 0,
            "{} failed: rc={} stdout={!r} stderr={!r}".format(
                description, result.get("rc"), result.get("stdout"), result.get("stderr")),
        )
        return result

    def inject_fault(self, fault_key, laser=0):
        """Inject a catalogued ELS laser fault and return its specification.

        Args:
            fault_key: key into ``CPO_FAULTS``.
            laser: zero-based ELS laser index, [0, 7]. Becomes
                ``lane_mask = 1 << laser``; a mask of 0 would be a silent
                no-op, so ``laser`` is a number here, never a mask. Each
                laser serves ``LANES_PER_LASER`` lanes.
        """
        pytest_assert(fault_key in CPO_FAULTS, "Unknown CPO fault '{}'".format(fault_key))
        pytest_assert(0 <= laser < LASERS_PER_VMODULE,
                      "CPO laser index must be in [0, {})".format(LASERS_PER_VMODULE))
        spec = CPO_FAULTS[fault_key]
        # Record intent before touching hardware so teardown still resets the
        # module if a command changes state and then returns an error. The
        # laser is kept too: clearing the fault selector in clear_faults()
        # needs the same lane_mask the injection used.
        self._injected.append((fault_key, laser))

        cmd = (
            "sudo mlxreg -d {mst} --reg_name PMFT "
            "-i module_index={els},sub_module=0,lane_mask={lane_mask} "
            "-s num_of_faults_to_trigger=1,fault_type={fault_type},"
            "time_interval_between_faults=1,set_laser_source_fault={fault} -y"
        ).format(
            mst=self._resolve_mst_dev(), els=self.els_index, lane_mask=1 << laser,
            fault_type=spec["fault_type"], fault=spec["laser_source_fault"],
        )
        self._run_checked(cmd, "PMFT CPO fault injection")
        return spec

    def clear_faults(self, ports=None):
        """Undo an injection completely, in the three steps it takes.

        No single step suffices:

        1. Clear the PMFT fault selector (``set_laser_source_fault=0``,
           i.e. ``no_fault_to_trigger``) for each lane mask that was
           injected. Without this the injection intent stays armed in the
           register.
        2. ``sfputil reset`` the vModule. This zeroes the pg1A:212-219
           hardware latch AND brings the port back up -- a laser fault
           such as ``laser_high_power_fault`` does not merely set an
           EEPROM flag, it takes the laser out, so the logical port on
           that laser goes oper-down until the module is reset. Skipping
           this leaves the port down, and ``target_vmodule`` then filters
           that vModule out of later tests for not being oper-up.
        3. Delete the STATE_DB ``xcvr_fault`` field. The feature is
           append-only -- no delete path -- so the token survives both of
           the steps above and stays for the life of the pmon container.

        Args:
            ports: logical ports whose xcvr_fault to delete. Defaults to
                just ``self.logical_port``; pass the whole vModule group
                when the fault was fanned out to all of its ports.
        """
        if not self._injected:
            return

        # Every step is attempted even if an earlier one fails, so a single
        # failed command cannot leave a selector armed or a port faulted for
        # later tests. Failures are reported together at the end.
        failures = []

        def _attempt(cmd, description):
            logger.info("%s: %s", description, cmd)
            result = self.duthost.shell(cmd, module_ignore_errors=True)
            if result.get("rc") != 0:
                failures.append("{} failed: rc={} stdout={!r} stderr={!r}".format(
                    description, result.get("rc"), result.get("stdout"), result.get("stderr")))

        # Step 1 - disarm the fault selector for every lane mask injected.
        try:
            mst = self._resolve_mst_dev()
        except AssertionError as err:
            failures.append("Resolve MST device failed: {}".format(err))
            mst = None
        if mst:
            for _, laser in self._injected:
                _attempt(
                    ("sudo mlxreg -d {mst} --reg_name PMFT "
                     "-i module_index={els},sub_module=0,lane_mask={lane_mask} "
                     "-s num_of_faults_to_trigger=0,fault_type=0,"
                     "time_interval_between_faults=0,set_laser_source_fault=0 -y").format(
                        mst=mst, els=self.els_index, lane_mask=1 << laser),
                    "Clear PMFT fault selector (laser {})".format(laser),
                )

        # Step 2 - reset the vModule: clears the HW latch and recovers the port.
        _attempt(
            "sudo sfputil reset {}".format(self.logical_port),
            "Reset CPO vModule after fault injection",
        )

        # Step 3 - reset the append-only STATE_DB token.
        clear_xcvr_fault(self.duthost, ports or [self.logical_port])

        self._injected = []
        pytest_assert(not failures, "CPO fault cleanup incomplete: " + "; ".join(failures))

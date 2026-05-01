"""
Local conftest for Cisco conversion tests.

Overrides the module-scoped `duthost_console` fixture from tests/conftest.py so it
binds to `enum_supervisor_dut_hostname` instead of `enum_rand_one_per_hwsku_hostname`.

Why this override is needed:
- test_xr_migration must run console operations against the supervisor (e.g.
  `show chassis modules midplane-status`, XR rollback / SONiC migration scripts).
- It declares `enum_supervisor_dut_hostname` to pin the test to the supervisor.
- The shared `duthost_console` in tests/conftest.py depends on
  `enum_rand_one_per_hwsku_hostname`. The shared `pytest_generate_tests`
  parametrizes only the first DUT-enumerator it finds in fixturenames (an
  elif chain), so `enum_supervisor_dut_hostname` gets parametrized but
  `enum_rand_one_per_hwsku_hostname` does not. The latter then raises
  `AttributeError: 'SubRequest' object has no attribute 'param'` during setup.
- Overriding here keeps the fix scoped to the conversion test directory and
  ensures the console is created against the supervisor, which is what these
  tests actually need.
"""

import logging

import pytest

from tests.common.helpers.dut_utils import (
    create_duthost_console,
    create_linecard_console,
    get_supervisor_for_linecard,
)
from tests.common.utilities import get_inventory_files

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def duthost_console(duthosts, enum_supervisor_dut_hostname, request, localhost,
                    conn_graph_facts, creds):
    """
    Provides a console connection to the supervisor DUT for conversion tests.

    Mirrors the behavior of tests/conftest.py::duthost_console but anchors on the
    supervisor hostname so it is compatible with tests that also depend on
    `enum_supervisor_dut_hostname`.

    Password ordering note:
    `dut_utils.create_duthost_console` builds the candidate password list as
    `[creds['sonicadmin_password'], ansible_altpassword] + ansible_altpasswords + ...`
    and `SSHConsoleConn.session_preparation` tries them in order. The conversion
    test rotates the SUP admin password to `ansible_altpasswords[0]`. After a
    rotation (including a partially-completed prior run), the running password
    is the rotated value, but `creds['sonicadmin_password']` may still hold the
    factory/default value because `get_dut_current_passwd` relies on mgmt-IP
    SSH which can be unavailable mid-conversion. Trying the wrong password
    first causes the console concentrator / SUP PAM to rate-limit and drop the
    SSH session (observed as `paramiko Socket is closed`) before the correct
    password is reached.

    To make the console fixture robust in that state, override
    `sonicadmin_password` on a shallow copy of `creds` so the rotated password
    is tried first. The original `creds` dict is left untouched for other
    fixtures.
    """
    duthost = duthosts[enum_supervisor_dut_hostname]
    inv_files = get_inventory_files(request)

    # The supervisor should not have a "supervisor for linecard" mapping, but
    # keep the same branching as the shared fixture so behavior is identical
    # if this fixture is ever reused for non-supervisor nodes.
    supervisor = get_supervisor_for_linecard(duthost, duthosts, inv_files)

    console_creds = dict(creds)
    alt_passwords = creds.get("ansible_altpasswords") or []
    if alt_passwords:
        rotated_password = alt_passwords[0]
        if console_creds.get("sonicadmin_password") != rotated_password:
            logger.info(
                "duthost_console: prefer rotated password (ansible_altpasswords[0]) "
                "over creds['sonicadmin_password'] for SUP %s console login",
                duthost.hostname,
            )
            console_creds["sonicadmin_password"] = rotated_password

    if supervisor:
        console = create_linecard_console(supervisor, duthost, inv_files, console_creds)
    else:
        console = create_duthost_console(duthost, localhost, conn_graph_facts, console_creds)

    yield console

    if console:
        try:
            console.disconnect()
        except Exception:
            pass

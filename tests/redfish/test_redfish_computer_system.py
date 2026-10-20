# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Nexthop AI
# Copyright (C) 2026 SONiC Project
# Author: Chinmoy Dey <chinmoy@nexthop.ai>
"""
Tests for the Redfish ComputerSystem the rack manager drives the switch host through.

    GET  /redfish/v1/Systems
    GET  /redfish/v1/Systems/system
    GET  /redfish/v1/Systems/system/ResetActionInfo
    POST /redfish/v1/Systems/system/Actions/ComputerSystem.Reset   (refused ResetTypes)

On the SONiC BMC the ComputerSystem is the switch host. bmcweb builds it from
the xyz.openbmc_project.State.Host object sonic-dbus-bridge mirrors from
bmcctld's HOST_STATE|switch-host row, so PowerState must agree with STATE_DB.
ComputerSystem.Reset may only offer the ResetTypes bmcctld carries out as a
RACK_MANAGER_COMMAND (On, ForceOff, GracefulShutdown, PowerCycle); every other
standard ResetType must be refused before it reaches the bridge, since stock
bmcweb maps ForceOn to a power-on, ForceRestart and GracefulRestart to reboots
and Nmi to an NMI the switch host has no line for.

Nothing here changes the switch host's power state.
"""
import logging
import time

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.sonic_db import STATE_DB, redis_hgetall, redis_keys
from tests.common.utilities import wait_until
from tests.redfish.redfish_utils import (
    HOST_FINAL_POWER_STATES,
    assert_field_contains,
    assert_field_equals,
    assert_member_count,
    assert_redfish_error,
    assert_status_ok,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

SYSTEMS_PATH = "/redfish/v1/Systems"
SYSTEM_PATH = "{}/system".format(SYSTEMS_PATH)
RESET_PATH = "{}/Actions/ComputerSystem.Reset".format(SYSTEM_PATH)
RESET_ACTION_INFO_PATH = "{}/ResetActionInfo".format(SYSTEM_PATH)
RESET_ACTION = "#ComputerSystem.Reset"

HOST_STATE_KEY = "HOST_STATE|switch-host"
COMMAND_KEY_GLOB = "RACK_MANAGER_COMMAND|*"

# The ResetTypes with a RACK_MANAGER_COMMAND behind them (sonic-dbus-bridge
# host_state_mapping.hpp): the only ones the reset action accepts and
# ResetActionInfo may advertise.
SUPPORTED_RESET_TYPES = {"On", "ForceOff", "GracefulShutdown", "PowerCycle"}
# Standard ResetTypes stock bmcweb would act on; the SONiC build must refuse them.
UNSUPPORTED_RESET_TYPES = ["ForceOn", "ForceRestart", "GracefulRestart", "Nmi"]

# Redfish PowerState for a HOST_STATE|switch-host row (sonic-redfish README, host
# state table): a transitional device_power_state maps directly, a settled one
# follows device_status.
TRANSITIONAL_POWER_STATES = {
    "POWERING_ON": "PoweringOn",
    "POWER_CYCLING": "PoweringOn",
    "POWERING_OFF": "PoweringOff",
    "GRACEFUL_SHUTTING_DOWN": "PoweringOff",
}
DEVICE_STATUS_POWER_STATES = {"ONLINE": "On", "OFFLINE": "Off"}
VALID_POWER_STATES = set(TRANSITIONAL_POWER_STATES.values()) | set(DEVICE_STATUS_POWER_STATES.values())

AGREEMENT_TIMEOUT = 30
AGREEMENT_POLL = 2
# Long enough for a reset bmcweb did forward to show up as a command row.
NO_COMMAND_SETTLE = 5


def expected_power_state(host_state):
    """PowerState the bridge derives from a HOST_STATE|switch-host row, or None if it would keep its last."""
    power_state = host_state.get("device_power_state")
    if power_state in TRANSITIONAL_POWER_STATES:
        return TRANSITIONAL_POWER_STATES[power_state]
    status = host_state.get("device_status")
    if status in DEVICE_STATUS_POWER_STATES:
        return DEVICE_STATUS_POWER_STATES[status]
    if power_state in HOST_FINAL_POWER_STATES:
        return DEVICE_STATUS_POWER_STATES[HOST_FINAL_POWER_STATES[power_state]]
    return None


def _reset_type_allowable_values(redfish_client):
    """AllowableValues of the ResetType parameter as ResetActionInfo advertises them."""
    response = redfish_client.get(RESET_ACTION_INFO_PATH)
    assert_status_ok(response, RESET_ACTION_INFO_PATH)
    body = response.json()
    parameters = [p for p in body.get("Parameters", []) if p.get("Name") == "ResetType"]
    pytest_assert(
        len(parameters) == 1,
        "{} must describe one ResetType parameter, got: {}".format(RESET_ACTION_INFO_PATH, body.get("Parameters"))
    )
    return body, parameters[0].get("AllowableValues", [])


class TestRedfishComputerSystem:

    def test_systems_collection_lists_system(self, redfish_client):
        """
        The Systems collection lists the switch host as /redfish/v1/Systems/system.

        That is the ComputerSystem the host power events name as
        OriginOfCondition, so a rack manager must reach it from the collection.
        """
        response = redfish_client.get(SYSTEMS_PATH)
        assert_status_ok(response, SYSTEMS_PATH)
        body = response.json()
        assert_field_equals(body, "@odata.id", SYSTEMS_PATH)
        assert_field_contains(body, "@odata.type", "ComputerSystemCollection")
        assert_member_count(body)
        members = [m.get("@odata.id") for m in body.get("Members", [])]
        pytest_assert(SYSTEM_PATH in members, "{} must list {}, got: {}".format(SYSTEMS_PATH, SYSTEM_PATH, members))
        logger.info("Verified %s lists %s", SYSTEMS_PATH, members)

    def test_system_advertises_reset_action(self, redfish_client):
        """
        The ComputerSystem is served with its identity, a PowerState and the reset action.

        SONiC runs none of the optional OpenBMC providers bmcweb consults for a
        ComputerSystem (xyz.openbmc_project.Settings, the serial console socket
        units), so the GET must answer 200 without them. The reset action must
        carry its target and the ResetActionInfo link a rack manager discovers
        the ResetTypes from.
        """
        response = redfish_client.get(SYSTEM_PATH)
        assert_status_ok(response, SYSTEM_PATH)
        body = response.json()
        assert_field_equals(body, "@odata.id", SYSTEM_PATH)
        assert_field_equals(body, "Id", "system")
        assert_field_contains(body, "@odata.type", "#ComputerSystem.")
        pytest_assert(
            body.get("PowerState") in VALID_POWER_STATES,
            "PowerState must be one of {}, got: {!r}".format(sorted(VALID_POWER_STATES), body.get("PowerState"))
        )
        reset = body.get("Actions", {}).get(RESET_ACTION, {})
        assert_field_equals(reset, "target", RESET_PATH)
        assert_field_equals(reset, "@Redfish.ActionInfo", RESET_ACTION_INFO_PATH)
        logger.info("Verified %s: PowerState=%s, %s target=%s ActionInfo=%s", SYSTEM_PATH, body["PowerState"],
                    RESET_ACTION, reset["target"], reset["@Redfish.ActionInfo"])

    def test_system_power_state_follows_host_state(self, redfish_client, bmc_duthost):
        """
        PowerState agrees with bmcctld's HOST_STATE|switch-host row.

        sonic-dbus-bridge mirrors the row onto State.Host CurrentHostState and
        bmcweb reports that as PowerState: a transitional device_power_state
        reads PoweringOn or PoweringOff, a settled one reads On or Off by its
        device_status. The two sides are read until they agree, since bmcctld
        may rewrite the row between one read and the other.
        """
        pyrequire(redis_hgetall(bmc_duthost, STATE_DB, HOST_STATE_KEY),
                  "{} is not published, bmcctld is not running on this BMC".format(HOST_STATE_KEY))
        state = {}

        def _agree():
            state["host"] = redis_hgetall(bmc_duthost, STATE_DB, HOST_STATE_KEY)
            state["expected"] = expected_power_state(state["host"])
            response = redfish_client.get(SYSTEM_PATH)
            state["redfish"] = response.json().get("PowerState") if response.status_code == 200 else None
            return state["expected"] is not None and state["redfish"] == state["expected"]

        wait_until(AGREEMENT_TIMEOUT, AGREEMENT_POLL, 0, _agree)
        pytest_assert(
            state["expected"] is not None,
            "{} does not resolve to a PowerState: {}".format(HOST_STATE_KEY, state["host"])
        )
        pytest_assert(
            state["redfish"] == state["expected"],
            "{} PowerState must be {} for {} {}, got: {!r}".format(
                SYSTEM_PATH, state["expected"], HOST_STATE_KEY, state["host"], state["redfish"])
        )
        logger.info("Verified PowerState=%s matches %s %s", state["redfish"], HOST_STATE_KEY, state["host"])

    def test_reset_action_info_advertises_supported_reset_types(self, redfish_client):
        """
        ResetActionInfo offers exactly the ResetTypes the reset action accepts.

        AllowableValues must be On, ForceOff, GracefulShutdown and PowerCycle,
        each with a RACK_MANAGER_COMMAND behind it. ForceOn and Nmi, which
        stock bmcweb adds, must not be offered since the POST refuses them.
        """
        body, allowed = _reset_type_allowable_values(redfish_client)
        assert_field_equals(body, "@odata.id", RESET_ACTION_INFO_PATH)
        assert_field_equals(body, "Id", "ResetActionInfo")
        pytest_assert(
            set(allowed) == SUPPORTED_RESET_TYPES and len(allowed) == len(SUPPORTED_RESET_TYPES),
            "ResetType AllowableValues must be exactly {}, got: {}".format(sorted(SUPPORTED_RESET_TYPES), allowed)
        )
        logger.info("Verified %s advertises ResetType AllowableValues %s", RESET_ACTION_INFO_PATH, allowed)

    @pytest.mark.parametrize("reset_type", UNSUPPORTED_RESET_TYPES)
    def test_reset_rejects_unsupported_reset_types(self, redfish_client, bmc_duthost, reset_type):
        """
        A standard ResetType the switch host cannot perform is refused and reaches nobody.

        POST ResetType=<ForceOn|ForceRestart|GracefulRestart|Nmi> must answer
        400 ActionParameterNotSupported for the ResetType parameter, create no
        RACK_MANAGER_COMMAND row and leave HOST_STATE as it was. The POST is
        only issued when ResetActionInfo does not offer the value, since a BMC
        that offers it would act on the switch host.
        """
        _, allowed = _reset_type_allowable_values(redfish_client)
        pyrequire(reset_type not in allowed,
                  "ResetActionInfo offers {}, a POST would act on the switch host".format(reset_type))
        keys_before = set(redis_keys(bmc_duthost, STATE_DB, COMMAND_KEY_GLOB))
        host_before = redis_hgetall(bmc_duthost, STATE_DB, HOST_STATE_KEY)

        response = redfish_client.post(RESET_PATH, json={"ResetType": reset_type})
        logger.info("POST {} ResetType={} -> {} {!r}".format(
            RESET_PATH, reset_type, response.status_code, response.text[:300]))
        assert_redfish_error(response, 400, "ActionParameterNotSupported", message_args=["ResetType", "Reset"])

        time.sleep(NO_COMMAND_SETTLE)
        new_keys = set(redis_keys(bmc_duthost, STATE_DB, COMMAND_KEY_GLOB)) - keys_before
        pytest_assert(
            not new_keys,
            "ResetType={} must not reach bmcctld, but wrote: {}".format(reset_type, sorted(new_keys))
        )
        host_after = redis_hgetall(bmc_duthost, STATE_DB, HOST_STATE_KEY)
        pytest_assert(
            host_after.get("device_power_state") == host_before.get("device_power_state"),
            "{} changed across a refused ResetType={}: {} -> {}".format(
                HOST_STATE_KEY, reset_type, host_before, host_after)
        )
        logger.info("Verified ResetType=%s refused with ActionParameterNotSupported, no command row, %s unchanged",
                    reset_type, HOST_STATE_KEY)

"""Contains functions used to verify control plane(APP_DB, STATE_DB) values."""
import collections
import json
import logging

from tests.common.dualtor.dual_tor_common import CableType
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

APP_DB = 0
STATE_DB = 6

DB_NAME_MAP = {
    APP_DB: "APP_DB",
    STATE_DB: "STATE_DB"
}

DB_SEPARATOR_MAP = {
    APP_DB: ":",
    STATE_DB: "|"
}

APP_DB_MUX_STATE_FIELDS = {
    "MUX_CABLE_TABLE": "state",  # <active/standby>
    "HW_MUX_CABLE_TABLE": "state",  # <active/standby>
}

STATE_DB_MUX_STATE_FIELDS = {
    "MUX_CABLE_TABLE": "state",  # <active/standby>
    "HW_MUX_CABLE_TABLE": "state",  # <active/standby>
    "MUX_LINKMGR_TABLE": "state"  # <healthy/unhealthy>
}

DB_CHECK_FIELD_MAP = {
    APP_DB: APP_DB_MUX_STATE_FIELDS,
    STATE_DB: STATE_DB_MUX_STATE_FIELDS
}


class DBChecker:

    def __init__(self, duthost, state, health, intf_names='all', cable_type=CableType.default_type):
        """
        Create a DBChecker object
        Args:
            duthost:    DUT host object (needs to be passed by calling function
                        from duthosts fixture)
            state:      The expected value for each of the `state` fields in both
                        tables
            health:     The expected value for the `state` field in the
                        MUX_LINKMGR_TABLE table (only needed for STATE_DB)
            intf_names: A list of the PORTNAME to check in each table, or 'all'
                        (by default) to check all MUX_CABLE interfaces
            cable_type: Select ports with specified cable_type to check.
        """
        self.duthost = duthost
        self.state = state
        self.health = health
        self.intf_names = intf_names
        self.cable_type = cable_type
        self._parse_intf_names()
        self.mismatch_ports = {}

    def _dump_db(self, db, key_pattern):
        """Dump redis database matching specificied key pattern"""
        command = "redis-dump -d {db} -k \"{key_pattern}\"".format(
            db=db, key_pattern=key_pattern)
        lines = self.duthost.shell(command)["stdout_lines"]
        db_dump = json.loads(lines[0])
        logger.debug(json.dumps(db_dump, indent=4))
        return db_dump

    def verify_db(self, db):
        pytest_assert(
            wait_until(30, 10, 0, self.get_mismatched_ports, db),
            "Database states don't match expected state {state},"
            "incorrect {db_name} values {db_states}"
            .format(state=self.state, db_name=DB_NAME_MAP[db],
                    db_states=json.dumps(self.mismatch_ports,
                                        indent=4,
                                        sort_keys=True)))

    def _parse_intf_names(self):
        mux_cable_table = self.duthost.get_running_config_facts()['MUX_CABLE']
        selected_intfs = set(
            _ for _ in mux_cable_table if mux_cable_table[_].get("cable_type", CableType.default_type) == self.cable_type
        )
        if self.intf_names == 'all':
            self.intf_names = selected_intfs
        else:
            for intf in self.intf_names:
                if intf not in selected_intfs:
                    raise ValueError("Interface %s not in %s cable type" % (intf, self.cable_type))
            self.intf_names = set(self.intf_names)

    def get_mismatched_ports(self, db):
        """
        Query db on `tor_host` and check if the mux-related fields match the
        expected values.

        The tables/fields checked are defined in DB_CHECK_FIELD_MAP

        Args:
            db:         Database number to check. Should be either 0 for APP_DB or
                        6 for STATE_DB
        """
        logger.info("Verifying {} values on {}: "
                    "expected state = {}, expected health = {}".format(
                                DB_NAME_MAP[db], self.duthost, self.state, self.health))

        mismatch_ports = {}
        separator = DB_SEPARATOR_MAP[db]

        db_check_fields = DB_CHECK_FIELD_MAP[db]
        for table, field in db_check_fields.items():
            key_pattern = table + separator + "*"
            db_dump = self._dump_db(db, key_pattern)

            if table == 'MUX_LINKMGR_TABLE':
                pytest_assert(
                    self.health is not None,
                    "Must give a value for `health` when checking STATE_DB values")
                target_value = self.health
            else:
                target_value = self.state

            for intf_name in self.intf_names:
                table_key = '{}{}{}'.format(table, separator, intf_name)

                if db_dump[table_key]['value'][field] != target_value:
                    mismatch_ports[table_key] = db_dump[table_key]['value']

        self.mismatch_ports = mismatch_ports

        return not bool(mismatch_ports)


def verify_tor_states(
    expected_active_host, expected_standby_host,
    expected_standby_health='healthy', intf_names='all',
    cable_type=CableType.default_type, skip_state_db=False
):
    """
    Verifies that the expected states for active and standby ToRs are
    reflected in APP_DB and STATE_DB on each device
    """
    if isinstance(expected_active_host, collections.Iterable):
        for duthost in expected_active_host:
            db_checker = DBChecker(duthost, 'active', 'healthy', intf_names=intf_names, cable_type=cable_type)
            db_checker.verify_db(APP_DB)
            if not skip_state_db:
                db_checker.verify_db(STATE_DB)
    elif expected_active_host is not None:
        duthost = expected_active_host
        db_checker = DBChecker(duthost, 'active', 'healthy', intf_names=intf_names, cable_type=cable_type)
        db_checker.verify_db(APP_DB)
        if not skip_state_db:
            db_checker.verify_db(STATE_DB)

    if isinstance(expected_standby_host, collections.Iterable):
        for duthost in expected_standby_host:
            db_checker = DBChecker(duthost, 'standby', expected_standby_health, intf_names=intf_names, cable_type=cable_type)
            db_checker.verify_db(APP_DB)
            if not skip_state_db:
                db_checker.verify_db(STATE_DB)
    elif expected_standby_host is not None:
        duthost = expected_standby_host
        db_checker = DBChecker(duthost, 'standby', expected_standby_health, intf_names=intf_names, cable_type=cable_type)
        db_checker.verify_db(APP_DB)
        if not skip_state_db:
            db_checker.verify_db(STATE_DB)

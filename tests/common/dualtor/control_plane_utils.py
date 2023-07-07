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
CONFIG_DB = 4

DB_NAME_MAP = {
    APP_DB: "APP_DB",
    STATE_DB: "STATE_DB",
    CONFIG_DB: "CONFIG_DB"
}

DB_SEPARATOR_MAP = {
    APP_DB: ":",
    STATE_DB: "|",
    CONFIG_DB: "|"
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

EXPECTED_TUNNEL_ROUTE_MAP = {
    CableType.active_standby: {
        "active": {},
        "standby": {
            "server_ipv4": {"asic": 1, "kernel":1},
            "server_ipv6": {"asic": 1, "kernel":1}
        },
        "stand_alone": {
            "server_ipv4": {"asic": 1, "kernel":0},
            "server_ipv6": {"asic": 1, "kernel":0}
        }
    },
    CableType.active_active: {
        "active": {},
        "standby": {
            "server_ipv4": {"asic": 1, "kernel":1},
            "server_ipv6": {"asic": 1, "kernel":1},
            "soc_ipv4": {"asic": 1, "kernel":0}
        },
        "stand_alone": {
            "server_ipv4": {"asic": 1, "kernel":0},
            "server_ipv6": {"asic": 1, "kernel":0},
            "soc_ipv4": {"asic": 1, "kernel":0}
        }
    }
}

class DBChecker:

    def __init__(self, duthost, state, health, intf_names='all',
                 cable_type=CableType.default_type, verify_db_timeout=30):
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
        self.VERIFY_DB_TIMEOUT = verify_db_timeout

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
            wait_until(self.VERIFY_DB_TIMEOUT, 10, 0, self.get_mismatched_ports, db),
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

                if table_key not in db_dump:
                    mismatch_ports[table_key] = {}
                elif db_dump[table_key]['value'][field] != target_value:
                    mismatch_ports[table_key] = db_dump[table_key]['value']

        self.mismatch_ports = mismatch_ports

        return not bool(mismatch_ports)
    
    def _get_nbr_data(self, intf_name, dest_name):
        """Fetch neighbor data"""
        ipaddress = self._get_ipaddr(intf_name, dest_name)
        if ipaddress == "":
            logger.debug("Failed to fetch {}'s {} address in config db. ".format(intf_name, dest_name))

            return False

        cmd = "/bin/ip neigh show " + ipaddress
        nbr_data = self.duthost.shell(cmd)['stdout']

        logger.debug("Fetched neighbor entry data for {} {}: {}".format(intf_name, dest_name, nbr_data))
        return nbr_data and nbr_data.startswith(ipaddress.split("/")[0])

    def _get_ipaddr(self, intf_name, dest_name):
        """Get IP address from mux cable table in config db"""
        tbl_name = "MUX_CABLE" + DB_SEPARATOR_MAP[CONFIG_DB] + intf_name
        db_dump = self._dump_db(CONFIG_DB, tbl_name)

        if tbl_name in db_dump:
            return db_dump[tbl_name]['value'].get(dest_name, "")
        
        return ""

    def _get_mux_tunnel_route(self):
        """Get output of show muxcable tunnel-route. """
        tunnel_route = json.loads(self.duthost.shell("show muxcable tunnel-route --json")['stdout'])
        
        logger.debug(json.dumps(tunnel_route, indent=4))
        return tunnel_route

    def get_tunnel_route_mismatched_ports(self, stand_alone):
        """Check if tunnel routes are added/removed respectively for standby/active interfaces"""
        logger.info("Verifying tunnel-route status on {}: expected state = {}".format(
                        self.duthost, self.state))
        
        mismatch_ports = {}
        tunnel_route = self._get_mux_tunnel_route()
        expected = EXPECTED_TUNNEL_ROUTE_MAP[self.cable_type]["stand_alone" if stand_alone else self.state]

        for intf in self.intf_names:
            routes = tunnel_route["TUNNEL_ROUTE"].get(intf, {})
            
            if expected == {}: 
                if routes != {}:
                    mismatch_ports[intf] = routes
            else:
                for dest_name in expected.keys():
                    if not self._get_nbr_data(intf, dest_name):
                        logger.debug("Skipping tunnel_route check for {} {} due to non-existing neighbor entry. ".format(intf, dest_name))
                        continue

                    if dest_name in routes: 
                        if not (int(routes[dest_name]["asic"]) == expected[dest_name]["asic"] 
                                    and int(routes[dest_name]["kernel"]) == expected[dest_name]["kernel"]):
                            mismatch_ports[intf] = routes
                    else:
                        mismatch_ports[intf] = routes
        
        self.tunnel_route_mismatched_ports = mismatch_ports
        
        return not bool(mismatch_ports)

    def verify_tunnel_route(self, stand_alone=False):
        pytest_assert(
            wait_until(self.VERIFY_DB_TIMEOUT, 10, 0, self.get_tunnel_route_mismatched_ports, stand_alone),
            "Tunnel route status doesn't match expected,"
            "incorrect interfaces: {}"
            .format(json.dumps(self.tunnel_route_mismatched_ports,
                                         indent=4,
                                         sort_keys=True)))


def verify_tor_states(
    expected_active_host, expected_standby_host,
    expected_standby_health='healthy', intf_names='all',
    cable_type=CableType.default_type, skip_state_db=False,
    skip_tunnel_route=True, standalone_tunnel_route=False,
    verify_db_timeout=30
):
    """
    Verifies that the expected states for active and standby ToRs are
    reflected in APP_DB and STATE_DB on each device
    """
    if not isinstance(expected_active_host, collections.Iterable):
        expected_active_host = [] if expected_active_host is None else [expected_active_host]
    for duthost in expected_active_host:
        db_checker = DBChecker(duthost, 'active', 'healthy',
                                intf_names=intf_names, cable_type=cable_type,
                                verify_db_timeout=verify_db_timeout)
        db_checker.verify_db(APP_DB)
        if not skip_state_db:
            db_checker.verify_db(STATE_DB)

        if not skip_tunnel_route:
            db_checker.verify_tunnel_route(standalone_tunnel_route)

    if not isinstance(expected_standby_host, collections.Iterable):
        expected_standby_host = [] if expected_standby_host is None else [expected_standby_host]
    for duthost in expected_standby_host:
        db_checker = DBChecker(duthost, 'standby', expected_standby_health,
                                intf_names=intf_names, cable_type=cable_type,
                                verify_db_timeout=verify_db_timeout)
        db_checker.verify_db(APP_DB)
        if not skip_state_db:
            db_checker.verify_db(STATE_DB)
        
        if not skip_tunnel_route:
            db_checker.verify_tunnel_route(standalone_tunnel_route)

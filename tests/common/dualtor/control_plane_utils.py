"""Contains functions used to verify control plane(APP_DB, STATE_DB) values."""

APP_DB = 0
STATE_DB = 6
APP_DB_MUX_STATE_FIELDS = {
    "MUX_CABLE_TABLE": "state",
    "HW_MUX_CABLE_TABLE": "state",
    "MUX_CABLE_RESPONSE_TABLE": "response"
}
STATE_DB_MUX_STATE_FIELDS = {
    "MUX_CABLE_TABLE": "state",
    "HW_MUX_CABLE_TABLE": "state"
}


def _keys(duthost, db, key_pattern):
    """Run Redis command keys over db on duthost."""
    command = "redis-cli --raw -n {db} keys '{key_pattern}'".format(db=db, key_pattern=key_pattern)
    keys_result = duthost.shell(command)
    if not keys_result["stdout"].strip():
        raise ValueError("No keys match key pattern {}".format(key_pattern))
    return [line.strip() for line in keys_result["stdout_lines"]]


def _hgetall(duthost, db, key):
    """Run Redis command hgetall over db on duthost."""
    command = "redis-cli --raw -n {db} hgetall '{key}'".format(db=db, key=key)
    lines = duthost.shell(command)["stdout_lines"]
    return {lines[i]: lines[i + 1] for i in range(0, len(lines), 2)}


def expect_app_db_values(duthost, intf_names, state):
    """
    Query APP_DB on `duthost` and check if mux cable fields match the given state.

    The following tables/fields are checked:

    MUX_CABLE_TABLE|PORTNAME:
        - state: <active|standby|unknown>

    HW_MUX_CABLE_TABLE|PORTNAME
        - state: <active|standby|unknown>

    MUX_CABLE_RESPONSE_TABLE|PORTNAME:
        - response: <active|standby|unknown>

    Args:
        duthost: DUT host object (needs to be passed by calling function from duthosts fixture)
        intf_names: A list of the PORTNAME to check in each table
        state: The expected value for each field in each table listed above.

    Returns:
        True if the mux cable fields match the given state.
    Raises:
        ValueError if the mux cable fields don't match the given state.
    """
    db = APP_DB
    mux_states = {}
    match = True
    for intf_name in intf_names:
        mux_states[intf_name] = {}
        for table, field in APP_DB_MUX_STATE_FIELDS.items():
            key = table + "|" + intf_name
            _keys(duthost, db, key)
            mux_states[intf_name][table] = _hgetall(duthost, db, key)
            if mux_states[intf_name][table][field] != state:
                match = False

    if not match:
        raise ValueError("Mux cable states unmatch, expect state: {state}, "
                         "actual APP_DB values: {db_states}".format(state=state, db_states=mux_states))
    return match


def expect_state_db_values(duthost, intf_names, state, health):
    """
    Query STATE_DB on `tor_host` and check if mux cable fields match the given states.

    The following tables/fields are checked:

    MUX_CABLE_TABLE|PORTNAME:
        - state: <active|standby|unknown>
        - health: <healthy|unhealthy>

    HW_MUX_CABLE_TABLE|PORTNAME:
        - state: <active|standby|unknown>

    Args:
        duthost: DUT host object (needs to be passed by calling function from duthosts fixture)
        intf_names: A list of the PORTNAME to check in each table
        state: The expected value for each of the `state` fields in both tables
        health: The expected value for the `health` field in the MUX_CABLE_TABLE table

    Returns:
        True if actual values match expected.
    Raises:
        ValueError if th mux cable fields don't match the given states.
    """
    db = STATE_DB
    mux_states = {}
    match = True
    for intf_name in intf_names:
        mux_states[intf_name] = {}
        for table, field in STATE_DB_MUX_STATE_FIELDS.items():
            key = table + "|" + intf_name
            _keys(duthost, db, key)
            mux_states[intf_name][table] = _hgetall(duthost, db, key)

            if mux_states[intf_name][table][field] != state:
                match = False

        if mux_states[intf_name]["MUX_CABLE_TABLE" + "|" + intf_name].get("health") != health:
            match = False

    if not match:
        raise ValueError("Mux cable states unmatch, expect state: {state}, "
                         "expect health: {health}, actual STATE_DB values: {db_states}".format(
                             state=state, db_states=mux_states, health=health))
    return match

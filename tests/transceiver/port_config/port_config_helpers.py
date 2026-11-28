"""CONFIG_DB PORT table checks for the Port Config test category.

Each ``check_*`` function compares a pre-read CONFIG_DB PORT table against the
expected values for the ports under test and returns a list of failure
strings, so test cases and scenario verifiers can aggregate them.
"""

PORT_FIELD_ADMIN_STATUS = "admin_status"
ADMIN_STATUS_UP = "up"


def check_admin_status(port_table, ports):
    """Return failures for ports whose CONFIG_DB ``admin_status`` is not ``up``."""
    failures = []
    for port in ports:
        port_config = port_table.get(port)
        if port_config is None:
            failures.append("{} missing from CONFIG_DB PORT table".format(port))
            continue
        admin_status = port_config.get(PORT_FIELD_ADMIN_STATUS)
        if admin_status != ADMIN_STATUS_UP:
            failures.append(
                "{} admin_status is {!r}, expected {!r}".format(
                    port, admin_status, ADMIN_STATUS_UP,
                )
            )
    return failures

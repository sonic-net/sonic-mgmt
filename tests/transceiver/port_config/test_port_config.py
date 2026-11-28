import logging

import pytest

from tests.transceiver.common.db_helpers import get_config_db_port_table
from tests.transceiver.port_config.port_config_helpers import check_admin_status

logger = logging.getLogger(__name__)


def test_port_admin_status_in_config_db(duthost, port_config_ports):
    """TC1: every inventory port has ``admin_status`` set to ``up`` in CONFIG_DB."""
    port_table = get_config_db_port_table(duthost)
    failures = check_admin_status(port_table, port_config_ports)

    if failures:
        pytest.fail("Port admin status validation failures:\n" + "\n".join(failures))

    logger.info("Port admin status passed for %d port(s)", len(port_config_ports))

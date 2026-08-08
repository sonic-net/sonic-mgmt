"""Shared constants for the Port Config test package.

Kept in a standalone module (not a test module) so conftest.py and the test
modules can both import them without conftest importing from a test module --
an anti-pattern that couples conftest import to test-module collection.
"""

# CONFIG_DB PORT table key template (Redis keys are ``TABLE|key``).
CONFIG_DB_PORT_KEY_TEMPLATE = "PORT|{}"

# CONFIG_DB PORT table field names validated by this category.
PORT_FIELD_ADMIN_STATUS = "admin_status"
PORT_FIELD_SPEED = "speed"
PORT_FIELD_FEC = "fec"
PORT_FIELD_MTU = "mtu"
PORT_FIELD_AUTONEG = "autoneg"
PORT_FIELD_DOM_POLLING = "dom_polling"
PORT_FIELD_SUBPORT = "subport"
PORT_FIELD_INDEX = "index"

# Expected admin status for a transceiver port under test.
ADMIN_STATUS_UP = "up"

# Speed (in Gbps) at or above which RS-FEC is mandatory.
FEC_REQUIRED_MIN_SPEED_GBPS = 200
FEC_MODE_RS = "rs"

# CONFIG_DB stores speed in Mbps as a string (e.g. "400000"); divide to Gbps.
MBPS_PER_GBPS = 1000

# DOM polling: absent field defaults to enabled per SONiC behaviour.
DOM_POLLING_ENABLED = "enabled"
DOM_POLLING_DISABLED = "disabled"

# subport value for a non-breakout port (when the field is present at all).
SUBPORT_NON_BREAKOUT = "0"

# Attribute keys sourced from BASE_ATTRIBUTES (dut_info) / PORT_CONFIG_ATTRIBUTES.
ATTR_SPEED_GBPS = "speed_gbps"
ATTR_HOST_LANE_MASK = "host_lane_mask"
ATTR_EXPECTED_MTU = "expected_mtu"
ATTR_EXPECTED_AUTONEG = "expected_autoneg"

"""Constants shared by DOM fixtures and test modules."""

DOM_CATEGORY_KEY = "DOM_ATTRIBUTES"

STATE_DB_SENSOR_KEY_TEMPLATE = "TRANSCEIVER_DOM_SENSOR|{}"
STATE_DB_THRESHOLD_KEY_TEMPLATE = "TRANSCEIVER_DOM_THRESHOLD|{}"
STATE_DB_INFO_KEY_TEMPLATE = "TRANSCEIVER_INFO|{}"

OPERATIONAL_SUFFIX = "_operational_range"
THRESHOLD_SUFFIX = "_threshold_range"
LANE_NUM_PLACEHOLDER = "LANE_NUM"

THRESHOLD_FIELD_SUFFIXES = ("lowalarm", "lowwarning", "highwarning", "highalarm")
THRESHOLD_PREFIX_OVERRIDES = {
    "temperature": "temp",
    "voltage": "vcc",
    "tx_power": "txpower",
    "rx_power": "rxpower",
    "tx_bias": "txbias",
    "laser_temperature": "lasertemp",
}
VALUE_TOLERANCE = 0.01

THRESHOLD_TO_OPERATIONAL_ATTR_CANDIDATES = {
    "tx_bias": ("txLANE_NUMbias_operational_range", "tx_bias_operational_range"),
    "tx_power": ("txLANE_NUMpower_operational_range", "tx_power_operational_range"),
    "rx_power": ("rxLANE_NUMpower_operational_range", "rx_power_operational_range"),
}

CONSISTENCY_VARIATION_THRESHOLD_ATTRS = (
    "tx_power_consistency_variation_threshold",
    "rx_power_consistency_variation_threshold",
    "tx_bias_consistency_variation_threshold",
    "laser_temperature_consistency_variation_threshold",
    "temperature_consistency_variation_threshold",
    "voltage_consistency_variation_threshold",
)

# operational range attribute -> (threshold attribute, mode)
# mode:
# - abs: absolute delta check
# - pct: percentage-of-previous-value delta check
CONSISTENCY_VARIATION_RULES = {
    "txLANE_NUMpower_operational_range": ("tx_power_consistency_variation_threshold", "abs"),
    "rxLANE_NUMpower_operational_range": ("rx_power_consistency_variation_threshold", "abs"),
    "txLANE_NUMbias_operational_range": ("tx_bias_consistency_variation_threshold", "pct"),
    "laser_temperature_operational_range": ("laser_temperature_consistency_variation_threshold", "abs"),
    "temperature_operational_range": ("temperature_consistency_variation_threshold", "abs"),
    "voltage_operational_range": ("voltage_consistency_variation_threshold", "abs"),
}

DOM_CORE_FILES_PATH = "/var/core"
DOM_HEALTH_CHECK_SERVICES = ("xcvrd", "pmon", "swss", "syncd")
DOM_POST_TEST_HEALTH_CHECK_SERVICES = ("xcvrd", "pmon")
DOM_SERVICE_MIN_UPTIME_SEC = 300

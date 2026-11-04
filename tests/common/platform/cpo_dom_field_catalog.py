"""
CPO DOM field catalog for SW-controlled CPO.

Lists STATE_DB TRANSCEIVER_* fields that must be published when both gates
are true: CPO platform and SW control.

The laser source (ELS) publishes into its own TRANSCEIVER_ELS_* tables, one
counterpart per optical-engine table; the engine tables no longer carry
``els_*`` fields.
"""

LANE_COUNT_PER_BANK = 8
LASER_COUNT_PER_ELS = 8


def _expand(template, count, start=1):
    """e.g. 'rx{n}power' -> ['rx1power', 'rx2power', ...]."""
    return [template.format(n=i) for i in range(start, start + count)]


# TRANSCEIVER_INFO: only CPO-invariant values are checked here; other CMIS
# identity fields are covered by existing regression suites.
TRANSCEIVER_INFO_LEGACY_VALUE_CHECKS = {
    "type":            "CPO",
    "type_abbrv_name": "CPO",
    "vdm_supported":   "True",
}


# ELS fields are always lanes 1..8, whatever OE bank the port is on: the laser
# source has its 8 lasers in one bank, so the platform reads it through bank 0
# and ElsfpApi numbers the lanes from that bank.
def _lanes(template):
    return _expand(template, LANE_COUNT_PER_BANK)


LEGACY_ELS_FIELD_PREFIX = "els_"

ELS_INFO_FIELDS = [
    "type", "type_abbrv_name", "hardware_rev", "serial", "manufacturer",
    "model", "connector", "encoding", "ext_identifier",
    "ext_rateselect_compliance", "cable_length", "nominal_bit_rate",
    "vendor_date", "vendor_oui", "cable_type", "media_interface_technology",
    "vendor_rev", "cmis_rev", "specification_compliance", "vdm_supported",
    "cdb_supported", "lane_count", "control_mode", "max_optical_power",
    "min_optical_power", "max_laser_bias", "min_laser_bias",
    "is_replaceable",
] + _lanes("fiber_mapping_lane{n}") + _lanes("frequency_lane{n}")

ELS_FIRMWARE_INFO_FIELDS = ["active_firmware", "inactive_firmware", "last_update_time"]

ELS_DOM_SENSOR_FIELDS = [
    "temperature", "voltage", "icc", "last_update_time",
] + _lanes("laser_bias_current_lane{n}") \
  + _lanes("optical_power_lane{n}") \
  + _lanes("voltage_lane{n}")
# Published via CDB 0x9018 (laser monitoring); not available on SIMX.
ELS_DOM_SENSOR_CDB_FIELDS = [
    "power_consumption",
] + _lanes("laser_mpd_lane{n}") \
  + _lanes("tec_voltage_lane{n}") \
  + _lanes("tec_health_value_lane{n}") \
  + _lanes("health_value_lane{n}")

ELS_DOM_TEMPERATURE_FIELDS = ["temperature", "last_update_time"]

ELS_DOM_THRESHOLD_FIELDS = [
    "laser_bias_alarm_high", "laser_bias_alarm_low",
    "laser_bias_warn_high", "laser_bias_warn_low",
    "optical_power_alarm_high", "optical_power_alarm_low",
    "optical_power_warn_high", "optical_power_warn_low",
    "temperature_alarm_high", "temperature_alarm_low",
    "temperature_warn_high", "temperature_warn_low",
    "voltage_alarm_high", "voltage_alarm_low",
    "voltage_warn_high", "voltage_warn_low",
    "last_update_time",
]

# Per-lane setpoints (ELSFP page 1Bh). Depending on the sonic-platform-common
# version they are published in TRANSCEIVER_ELS_DOM_THRESHOLD or in
# TRANSCEIVER_ELS_DOM_SENSOR; either is accepted.
ELS_SETPOINT_FIELDS = _lanes("bias_current_setpoint_lane{n}") \
  + _lanes("optical_power_setpoint_lane{n}")
ELS_SETPOINT_TABLES = ("TRANSCEIVER_ELS_DOM_THRESHOLD", "TRANSCEIVER_ELS_DOM_SENSOR")

ELS_DOM_FLAG_FIELDS = [
    "temperature_alarm_high", "temperature_alarm_low",
    "temperature_warn_high", "temperature_warn_low",
    "voltage_alarm_high", "voltage_alarm_low",
    "voltage_warn_high", "voltage_warn_low",
    "last_update_time",
] + [
    template.format(n=n)
    for n in range(1, LANE_COUNT_PER_BANK + 1)
    for template in (
        "laser_bias_alarm_high_lane{n}", "laser_bias_alarm_low_lane{n}",
        "optical_power_alarm_high_lane{n}", "optical_power_alarm_low_lane{n}",
        "laser_bias_warn_high_lane{n}", "laser_bias_warn_low_lane{n}",
        "optical_power_warn_high_lane{n}", "optical_power_warn_low_lane{n}",
    )
]

ELS_STATUS_FIELDS = [
    "module_state", "last_update_time",
] + _lanes("enable_lane{n}") \
  + _lanes("state_lane{n}") \
  + _lanes("output_fiber_checked_lane{n}") \
  + _lanes("fault_code_lane{n}") \
  + _lanes("warning_code_lane{n}")

ELS_STATUS_FLAG_FIELDS = [
    "lane_summary_fault", "lane_summary_warning",
    "datapath_firmware_fault", "module_firmware_fault",
    "module_state_changed", "last_update_time",
] + _lanes("fault_flag_lane{n}") + _lanes("warning_flag_lane{n}")


# STATE_DB-only fields the ELS platform API (chassis.get_cpo(i).elsfp.get_api())
# does not return.
_ELS_STATE_DB_ONLY_FIELDS = ("last_update_time", "is_replaceable")


def _els_api_fields(fields):
    return [f for f in fields if f not in _ELS_STATE_DB_ONLY_FIELDS]


# Keys that get_elsfp_* must return. Same names as the TRANSCEIVER_ELS_* tables
# (no ``els_`` prefix) minus the STATE_DB-only fields.
ELS_API_INFO_FIELDS = _els_api_fields(ELS_INFO_FIELDS)
ELS_API_FIRMWARE_INFO_FIELDS = _els_api_fields(ELS_FIRMWARE_INFO_FIELDS)
# CDB-backed sensors are hardware-only, so they are not required.
ELS_API_DOM_REAL_VALUE_FIELDS = _els_api_fields(ELS_DOM_SENSOR_FIELDS) + ELS_SETPOINT_FIELDS
ELS_API_THRESHOLD_FIELDS = _els_api_fields(ELS_DOM_THRESHOLD_FIELDS)
ELS_API_DOM_FLAG_FIELDS = _els_api_fields(ELS_DOM_FLAG_FIELDS)
ELS_API_STATUS_FIELDS = _els_api_fields(ELS_STATUS_FIELDS)
ELS_API_STATUS_FLAG_FIELDS = _els_api_fields(ELS_STATUS_FLAG_FIELDS)


def _per_lane(templates):
    """Expand each template for lanes 1..LANE_COUNT_PER_BANK, lane-major."""
    return [
        t.format(n=n)
        for n in range(1, LANE_COUNT_PER_BANK + 1)
        for t in templates
    ]


_LAST_UPDATE = ["last_update_time"]

OE_INFO_FIELDS = [
    "type", "type_abbrv_name", "manufacturer", "model", "serial",
    "vendor_rev", "hardware_rev", "vendor_oui", "vendor_date", "cmis_rev",
    "connector", "encoding", "ext_identifier", "ext_rateselect_compliance",
    "cable_type", "cable_length", "nominal_bit_rate",
    "specification_compliance", "application_advertisement",
    "media_interface_technology", "media_lane_count", "host_lane_count",
    "vdm_supported", "is_replaceable",
] + _lanes("active_apsel_hostlane{n}")

OE_FIRMWARE_INFO_FIELDS = ["active_firmware", "inactive_firmware"] + _LAST_UPDATE

OE_DOM_SENSOR_FIELDS = (
    ["temperature", "voltage"] + _LAST_UPDATE
    + _per_lane(["rx{n}power", "tx{n}power"])
)

OE_DOM_TEMPERATURE_FIELDS = ["temperature"] + _LAST_UPDATE

OE_DOM_THRESHOLD_FIELDS = [
    "{}{}".format(sensor, level)
    for sensor in ("temp", "vcc", "rxpower", "txpower")
    for level in ("highalarm", "lowalarm", "highwarning", "lowwarning")
] + _LAST_UPDATE

OE_DOM_FLAG_FIELDS = [
    "{}{}".format(sensor, level)
    for sensor in ("temp", "vcc")
    for level in ("HAlarm", "LAlarm", "HWarn", "LWarn")
] + _per_lane([
    "{}{{n}}{}{}".format(prefix, kind, level)
    for prefix, kind in (("tx", "power"), ("rx", "power"))
    for level in ("HAlarm", "LAlarm", "HWarn", "LWarn")
]) + _LAST_UPDATE

OE_STATUS_FIELDS = (
    ["module_state", "module_fault_cause", "tx_disabled_channel"] + _LAST_UPDATE
    + _per_lane([
        "DP{n}State", "tx{n}OutputStatus",
        "tx{n}disable", "config_state_hostlane{n}", "dpdeinit_hostlane{n}",
        "dpinit_pending_hostlane{n}",
    ])
)

OE_STATUS_FLAG_FIELDS = (
    ["datapath_firmware_fault", "module_firmware_fault", "module_state_changed"]
    + _LAST_UPDATE
    + _per_lane([
        "tx{n}fault", "rx{n}los", "tx{n}los_hostlane",
    ])
)

# Standard CMIS VDM (pages 20h-2Fh) read from the optical engine; one sample
# per lane. Not emulated on SIMX. ``els_input_power{n}`` (VDM ID 84) is a
# standard CMIS VDM name, not a legacy laser-source field.
OE_VDM_REAL_VALUE_FIELDS = _lanes("laser_age{n}")

# Optical-engine STATE_DB table -> {els: required engine fields (key kept for
# symmetry with the ELS spec), value_check: {field: expected},
# allow_els_prefix: skip the legacy-field check}. Engine rows must otherwise be
# free of legacy ``els_*`` fields.
CPO_OE_TABLE_SPEC = {
    "TRANSCEIVER_INFO": {
        "els": OE_INFO_FIELDS,
        "value_check": TRANSCEIVER_INFO_LEGACY_VALUE_CHECKS,
    },
    "TRANSCEIVER_FIRMWARE_INFO":   {"els": OE_FIRMWARE_INFO_FIELDS},
    "TRANSCEIVER_DOM_SENSOR":      {"els": OE_DOM_SENSOR_FIELDS},
    "TRANSCEIVER_DOM_TEMPERATURE": {"els": OE_DOM_TEMPERATURE_FIELDS},
    "TRANSCEIVER_DOM_THRESHOLD":   {"els": OE_DOM_THRESHOLD_FIELDS},
    "TRANSCEIVER_DOM_FLAG":        {"els": OE_DOM_FLAG_FIELDS},
    "TRANSCEIVER_STATUS":          {"els": OE_STATUS_FIELDS},
    "TRANSCEIVER_STATUS_FLAG":     {"els": OE_STATUS_FLAG_FIELDS},
    "TRANSCEIVER_VDM_REAL_VALUE": {
        "els": OE_VDM_REAL_VALUE_FIELDS,
        "allow_els_prefix": True,
    },
}

# Laser-source STATE_DB table -> {els: required fields,
#                                 cdb_els: fields that need CDB (skipped on SIMX),
#                                 value_check: {field: expected value}}
# The *_FLAG tables also carry CHANGE_COUNT / SET_TIME / CLEAR_TIME companions
# (see CPO_ELS_COMPANION_TABLES), whose existence is checked per port.
CPO_ELS_TABLE_SPEC = {
    "TRANSCEIVER_ELS_INFO":           {"els": ELS_INFO_FIELDS},
    "TRANSCEIVER_ELS_FIRMWARE_INFO":  {"els": ELS_FIRMWARE_INFO_FIELDS},
    "TRANSCEIVER_ELS_DOM_SENSOR": {
        "els": ELS_DOM_SENSOR_FIELDS,
        "cdb_els": ELS_DOM_SENSOR_CDB_FIELDS,
    },
    "TRANSCEIVER_ELS_DOM_TEMPERATURE": {"els": ELS_DOM_TEMPERATURE_FIELDS},
    "TRANSCEIVER_ELS_DOM_THRESHOLD":  {"els": ELS_DOM_THRESHOLD_FIELDS},
    "TRANSCEIVER_ELS_DOM_FLAG":       {"els": ELS_DOM_FLAG_FIELDS},
    "TRANSCEIVER_ELS_STATUS":         {"els": ELS_STATUS_FIELDS},
    "TRANSCEIVER_ELS_STATUS_FLAG":    {"els": ELS_STATUS_FLAG_FIELDS},
}

_FLAG_COMPANION_SUFFIXES = ("CHANGE_COUNT", "SET_TIME", "CLEAR_TIME")


def _flag_companions(flag_tables):
    """CHANGE_COUNT / SET_TIME / CLEAR_TIME companions of each FLAG table."""
    return tuple(
        "{}_{}".format(base, suffix)
        for base in flag_tables
        for suffix in _FLAG_COMPANION_SUFFIXES
    )


CPO_ELS_COMPANION_TABLES = _flag_companions(
    ("TRANSCEIVER_ELS_DOM_FLAG", "TRANSCEIVER_ELS_STATUS_FLAG"))

CPO_OE_COMPANION_TABLES = _flag_companions(
    ("TRANSCEIVER_DOM_FLAG", "TRANSCEIVER_STATUS_FLAG"))

# VDM threshold and flag tables (plus the flag companions) published by xcvrd
# next to TRANSCEIVER_VDM_REAL_VALUE, one per threshold type.
_VDM_THRESHOLD_TYPES = ("HALARM", "LALARM", "HWARN", "LWARN")
_VDM_FLAG_TABLES = tuple(
    "TRANSCEIVER_VDM_{}_FLAG".format(t) for t in _VDM_THRESHOLD_TYPES)
CPO_VDM_TABLES = tuple(
    "TRANSCEIVER_VDM_{}_THRESHOLD".format(t) for t in _VDM_THRESHOLD_TYPES
) + _VDM_FLAG_TABLES + _flag_companions(_VDM_FLAG_TABLES)


# Tables checked only on real HW, skipped on SIMX: the *_DOM_TEMPERATURE tables
# are published by xcvrd's thermal task, which runs only when pmon sets
# xcvrd.dom_temperature_poll_interval (not set on SIMX, where thermal control
# was never validated), and SIMX does not emulate VDM.
CPO_SIMX_SKIPPED_TABLES = frozenset((
    "TRANSCEIVER_DOM_TEMPERATURE",
    "TRANSCEIVER_ELS_DOM_TEMPERATURE",
    "TRANSCEIVER_VDM_REAL_VALUE",
) + CPO_VDM_TABLES)


# Tables whose rows carry ``last_update_time`` and are refreshed by the DOM
# polling loop. Excluded on purpose: INFO (no timestamp), the *_FLAG companion
# tables (no timestamp), DOM_THRESHOLD and the VDM thresholds (static, written
# once, so their timestamp is never refreshed).
CPO_REFRESHED_TABLES = (
    "TRANSCEIVER_DOM_SENSOR",
    "TRANSCEIVER_DOM_TEMPERATURE",
    "TRANSCEIVER_DOM_FLAG",
    "TRANSCEIVER_FIRMWARE_INFO",
    "TRANSCEIVER_STATUS",
    "TRANSCEIVER_STATUS_FLAG",
    "TRANSCEIVER_ELS_DOM_SENSOR",
    "TRANSCEIVER_ELS_DOM_TEMPERATURE",
    "TRANSCEIVER_ELS_DOM_FLAG",
    "TRANSCEIVER_ELS_FIRMWARE_INFO",
    "TRANSCEIVER_ELS_STATUS",
    "TRANSCEIVER_ELS_STATUS_FLAG",
    "TRANSCEIVER_VDM_REAL_VALUE",
)
# DOM refresh interval is 60 s; ``last_update_time`` is written in UTC.
CPO_LAST_UPDATE_MAX_AGE_SEC = 60
# A ``last_update_time`` ahead of the DUT clock is not a recent update. The
# timestamp has 1 s resolution and is written by the same host, so only a
# small rounding margin is allowed.
CPO_LAST_UPDATE_FUTURE_TOLERANCE_SEC = 2

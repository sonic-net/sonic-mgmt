# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
CPO CLI field catalog for ``cpoutil show interface dom -p <port>``.

On CPO platforms ``sfputil`` is not supported and ``sfpshow`` no longer prints
ELS data; ``cpoutil`` is the CLI for the CPO / ELS fields.  Each entry maps a
``--json`` key to the label the table form prints for it:

    --json : {<port>: {"oe"|"els": {"info"|"dom"|"thresholds": {key: value}}}}
    table  : <port>: CPO EEPROM detected
                 OE: | ELS:
                     <Section>:
                         <label>: <value>

The groups follow the "DOM Fields That Should Appear" list for
``cpoutil show interface dom``:

  * Optical engine (OE): identity, channel monitors, channel thresholds,
    module monitors and thresholds (no laser temperature / Tx bias: the OE
    does not report them)
  * Laser source (ELS): identity, monitors, ELSFP thresholds, additional
    (setpoints), and the CDB-backed additional fields, which only hardware
    setups provide (SIMX does not answer the CDB)

``cpoutil`` combines ``cable_type`` and ``cable_length`` into one field named
after the cable type (``{cable_type: cable_length}``) in both output forms.

Per-lane keys use ``{n}``; the helper expands it with the lanes of the group's
endpoint found in the output (OE: ``rx{n}power``, ELS:
``laser_bias_current_lane{n}``).  Only the presence of each field is checked,
not its value.  The table omits DOM values that are ``N/A``, so a label is
required only when its ``--json`` value is not ``N/A``.  When sonic-utilities
or the platform renames a key or label, this file is the single place to
update.
"""
from collections import namedtuple

# ``fields``: {json key: table label}.  ``section`` is the table section under
# the endpoint header; ``""`` means directly under ``OE:`` / ``ELS:``.
FieldGroup = namedtuple(
    "FieldGroup", "name endpoint json_group section fields")


def _additional(*keys):
    """``AdditionalValues`` labels are the key with ``_`` replaced by blanks."""
    return {key: key.replace("_", " ") for key in keys}


def _thresholds(*bases):
    """``{base}{high|low}{alarm|warning}`` keys -> ``{Base}{High|Low}{Alarm|Warning}``."""
    return {
        f"{key}{level}{kind}": f"{label}{level.capitalize()}{kind.capitalize()}"
        for key, label in bases
        for level in ("high", "low")
        for kind in ("alarm", "warning")
    }


# Combined cable field: the CMIS ``cable_type`` descriptor of an attached
# optics module, holding the ``cable_length`` value.
CPO_CABLE_LENGTH_FIELD = "Length Cable Assembly(m)"

# Identity fields printed for both the OE and the ELS.
_IDENTITY = {
    "cmis_rev":                   "CMIS Revision",
    "type":                       "Identifier",
    "type_abbrv_name":            "Identifier Abbreviation",
    "manufacturer":               "Vendor Name",
    "vendor_oui":                 "Vendor OUI",
    "model":                      "Vendor PN",
    "vendor_rev":                 "Vendor Rev",
    "serial":                     "Vendor SN",
    "vendor_date":                "Vendor Date Code(YYYY-MM-DD Lot)",
    "hardware_rev":               "Hardware Revision",
    "connector":                  "Connector",
    "encoding":                   "Encoding",
    "ext_identifier":             "Extended Identifier",
    "ext_rateselect_compliance":  "Extended RateSelect Compliance",
    "media_interface_technology": "Media Interface Technology",
    CPO_CABLE_LENGTH_FIELD:       CPO_CABLE_LENGTH_FIELD,
    "nominal_bit_rate":           "Nominal Bit Rate(100Mbs)",
    "specification_compliance":   "Specification Compliance",
    "vdm_supported":              "VDM Supported",
}

# Rx power and Tx power thresholds of the OE ``ChannelThresholdValues``.
_OE_CHANNEL_THRESHOLDS = _thresholds(("rxpower", "RxPower"), ("txpower", "TxPower"))

CPO_DOM_FIELD_GROUPS = [
    # ---- Optical engine ----
    FieldGroup("OE identity", "oe", "info", "", {
        **_IDENTITY,
        "active_apsel_hostlane{n}":  "Active App Selection Host Lane {n}",
        "application_advertisement": "Application Advertisement",
        "host_lane_count":           "Host Lane Count",
        "media_lane_count":          "Media Lane Count",
    }),
    FieldGroup("OE channel monitors", "oe", "dom", "ChannelMonitorValues", {
        "rx{n}power": "RX{n}Power",
        "tx{n}power": "TX{n}Power",
    }),
    FieldGroup("OE channel thresholds", "oe", "thresholds", "ChannelThresholdValues",
               _OE_CHANNEL_THRESHOLDS),
    FieldGroup("OE module monitors", "oe", "dom", "ModuleMonitorValues", {
        "temperature": "Temperature",
        "voltage":     "Vcc",
    }),
    FieldGroup("OE module thresholds", "oe", "thresholds", "ModuleThresholdValues",
               _thresholds(("temp", "Temp"), ("vcc", "Vcc"))),

    # ---- Laser source (ELS) ----
    FieldGroup("ELS identity", "els", "info", "", {
        **_IDENTITY,
        "control_mode":          "Control Mode",
        "lane_count":            "Laser Count",
        "max_laser_bias":        "Maximum Laser Bias",
        "min_laser_bias":        "Minimum Laser Bias",
        "max_optical_power":     "Maximum Optical Power",
        "min_optical_power":     "Minimum Optical Power",
        "cdb_supported":         "CDB Supported",
        "fiber_mapping_lane{n}": "Laser {n} Fiber Mapping",
        "frequency_lane{n}":     "Laser {n} Frequency",
    }),
    FieldGroup("ELS monitors", "els", "dom", "MonitorValues", {
        "temperature":                "Temperature",
        "voltage":                    "Vcc",
        "icc":                        "Icc",
        "laser_bias_current_lane{n}": "Laser {n} Bias Current",
        "optical_power_lane{n}":      "Laser {n} Optical Power",
        "voltage_lane{n}":            "Laser {n} Voltage",
    }),
    FieldGroup("ELS ELSFP thresholds", "els", "thresholds", "ThresholdValues", {
        "temperature_alarm_high":   "TempHighAlarm",
        "temperature_alarm_low":    "TempLowAlarm",
        "temperature_warn_high":    "TempHighWarning",
        "temperature_warn_low":     "TempLowWarning",
        "voltage_alarm_high":       "VccHighAlarm",
        "voltage_alarm_low":        "VccLowAlarm",
        "voltage_warn_high":        "VccHighWarning",
        "voltage_warn_low":         "VccLowWarning",
        "optical_power_alarm_high": "TxPowerHighAlarm",
        "optical_power_alarm_low":  "TxPowerLowAlarm",
        "optical_power_warn_high":  "TxPowerHighWarning",
        "optical_power_warn_low":   "TxPowerLowWarning",
        "laser_bias_alarm_high":    "TxBiasHighAlarm",
        "laser_bias_alarm_low":     "TxBiasLowAlarm",
        "laser_bias_warn_high":     "TxBiasHighWarning",
        "laser_bias_warn_low":      "TxBiasLowWarning",
    }),
    FieldGroup("ELS additional", "els", "dom", "AdditionalValues",
               _additional("bias_current_setpoint_lane{n}",
                           "optical_power_setpoint_lane{n}")),
]

# ELS additional fields read through the NVIDIA ELS CDB 0x9018 command --
# available only on hardware setups.
CPO_DOM_CDB_FIELD_GROUPS = [
    FieldGroup("ELS additional (CDB)", "els", "dom", "AdditionalValues",
               _additional("laser_mpd_lane{n}",
                           "health_value_lane{n}",
                           "tec_health_value_lane{n}",
                           "tec_voltage_lane{n}",
                           "power_consumption")),
]

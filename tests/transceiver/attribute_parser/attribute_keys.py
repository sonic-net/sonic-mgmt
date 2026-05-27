"""Attribute category key constants for port_attributes_dict.

Each key corresponds to a JSON file in ansible/files/transceiver/inventory/attributes/
and is derived by AttributeManager via the filename-to-key convention:
Example
    eeprom.json        -> EEPROM_ATTRIBUTES

BASE_ATTRIBUTES is a special case populated from dut_info/<dut_hostname>.json
by DutInfoLoader, not from a category JSON file.
"""

BASE_ATTRIBUTES_KEY = "BASE_ATTRIBUTES"
EEPROM_ATTRIBUTES_KEY = "EEPROM_ATTRIBUTES"
SYSTEM_ATTRIBUTES_KEY = "SYSTEM_ATTRIBUTES"
PHYSICAL_OIR_ATTRIBUTES_KEY = "PHYSICAL_OIR_ATTRIBUTES"
REMOTE_RESEAT_ATTRIBUTES_KEY = "REMOTE_RESEAT_ATTRIBUTES"
CDB_FW_UPGRADE_ATTRIBUTES_KEY = "CDB_FW_UPGRADE_ATTRIBUTES"
DOM_ATTRIBUTES_KEY = "DOM_ATTRIBUTES"
VDM_ATTRIBUTES_KEY = "VDM_ATTRIBUTES"
PM_ATTRIBUTES_KEY = "PM_ATTRIBUTES"
PORT_CONFIG_ATTRIBUTES_KEY = "PORT_CONFIG_ATTRIBUTES"

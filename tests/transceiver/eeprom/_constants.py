"""Shared constants for the EEPROM test package.

Kept in a standalone module so the sfputil test, the show-CLI test, and any
future EEPROM-touching test all agree on the same plan-level defaults.
"""

# Plan-documented default for ``eeprom_dump_timeout_sec`` when the per-port
# inventory does not define it (see eeprom_test_plan.md, attributes table).
DEFAULT_EEPROM_DUMP_TIMEOUT_SEC = 5

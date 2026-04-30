"""
Test for ConfigDb utility class.

Validates the dict-like interface for reading and writing CONFIG_DB.
"""
import pytest
from spytest import st

import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
common_dir = os.path.join(current_dir, '..', 'common')
if common_dir not in sys.path:
    sys.path.insert(0, common_dir)

from config_db import ConfigDb, ConfigDbError
from tests.cisco.common.oci_test_helper import fail_test, pass_test


class TestConfigDb:
    """Test ConfigDb read/write operations."""

    def test_config_db_read_and_write(self):
        """
        Test ConfigDb read access and write-through functionality.

        Steps:
        1. Load CONFIG_DB
        2. Read a known table (DSCP_TO_TC_MAP)
        3. Modify a value
        4. Verify the change persists by reloading
        5. Restore original value
        """
        # Get first available DUT
        testbed_vars = st.get_testbed_vars()
        dut = getattr(testbed_vars, 'D1', None)
        if not dut:
            fail_test("No DUT available")

        st.banner("TEST: Loading CONFIG_DB")
        config = ConfigDb(dut)

        # Verify we can iterate tables
        tables = list(config.keys())
        st.log(f"Found {len(tables)} tables in CONFIG_DB")
        if len(tables) == 0:
            fail_test("CONFIG_DB appears empty")

        # Test read access on DSCP_TO_TC_MAP
        st.banner("TEST: Reading DSCP_TO_TC_MAP")

        if "DSCP_TO_TC_MAP" not in config:
            fail_test("DSCP_TO_TC_MAP not found in CONFIG_DB")

        dscp_maps = config["DSCP_TO_TC_MAP"]
        map_names = list(dscp_maps.keys())
        st.log(f"Found DSCP_TO_TC maps: {map_names}")

        if not map_names:
            fail_test("No DSCP_TO_TC maps configured")

        # Pick first map and read a value
        test_map_name = map_names[0]
        test_dscp = "10"

        dscp_map = config["DSCP_TO_TC_MAP"][test_map_name]
        if test_dscp not in dscp_map:
            fail_test(f"DSCP {test_dscp} not in map {test_map_name}")

        original_tc = dscp_map[test_dscp]
        st.log(f"Original: DSCP {test_dscp} -> TC {original_tc}")

        # Test write operation
        st.banner("TEST: Writing to CONFIG_DB")

        # Choose a different TC value
        new_tc = "7" if original_tc != "7" else "6"
        st.log(f"Setting DSCP {test_dscp} -> TC {new_tc}")

        config["DSCP_TO_TC_MAP"][test_map_name][test_dscp] = new_tc

        # Refresh and verify
        st.banner("TEST: Verifying write persisted")

        config.refresh()
        updated_tc = config["DSCP_TO_TC_MAP"][test_map_name][test_dscp]
        st.log(f"After reload: DSCP {test_dscp} -> TC {updated_tc}")

        if updated_tc != new_tc:
            # Try to restore before failing
            config["DSCP_TO_TC_MAP"][test_map_name][test_dscp] = original_tc
            fail_test(f"Write did not persist: expected TC={new_tc}, got TC={updated_tc}")

        # Restore original value
        st.banner("TEST: Restoring original value")

        config["DSCP_TO_TC_MAP"][test_map_name][test_dscp] = original_tc
        config.refresh()

        restored_tc = config["DSCP_TO_TC_MAP"][test_map_name][test_dscp]
        st.log(f"Restored: DSCP {test_dscp} -> TC {restored_tc}")

        if restored_tc != original_tc:
            fail_test(f"Restore failed: expected TC={original_tc}, got TC={restored_tc}")

        pass_test("ConfigDb read/write operations working correctly")

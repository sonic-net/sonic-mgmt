import logging
import pytest
import json
import os
import tempfile
from datetime import datetime

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import generate_tmpfile
from tests.common.gu_utils import create_checkpoint, delete_checkpoint
from tests.common import config_reload

logger = logging.getLogger(__name__)

# Test configurations
CONFIG_DB_PATH = "/etc/sonic/config_db.json"
CHECKPOINT_PATH = "/etc/sonic/checkpoints/"

# Test data
TEST_VLAN_ID = "100"
TEST_PORTCHANNEL = "PortChannel001"
TEST_SYSLOG_SERVER = "10.0.0.100"
TEST_NTP_SERVER = "10.0.0.200"
TEST_TACACS_SERVER = "10.0.0.50"

pytestmark = [
    pytest.mark.topology('any')
]


class TestConfigReplace:
    @pytest.fixture(autouse=True)
    def setup_teardown(self, rand_selected_dut):
        """Setup and teardown for each test case"""
        self.duthost = rand_selected_dut
        self.tmp_files = []

        # Get initial config once
        config = self.duthost.shell("sonic-cfggen -d --print-data")
        pytest_assert(not config['rc'], "Failed to get initial configuration")
        self.initial_config = json.loads(config['stdout'])

        # Setup
        with tempfile.NamedTemporaryFile(prefix="config_db_backup_", suffix=".json", delete=False) as f:
            self.backup_file = f.name
        self.duthost.shell(f"cp {CONFIG_DB_PATH} {self.backup_file}")

        yield

        # Teardown
        if hasattr(self, 'backup_file'):
            self.duthost.shell(f"cp {self.backup_file} {CONFIG_DB_PATH}")
            config_reload(self.duthost)
            os.unlink(self.backup_file)

        self.cleanup_tmp_files()

    def cleanup_tmp_files(self):
        """Clean up temporary files"""
        for tmp_file in self.tmp_files:
            try:
                os.unlink(tmp_file)
            except OSError:
                pass

    def get_initial_config(self):
        """Get initial configuration"""
        return dict(self.initial_config)

    def get_current_config(self):
        """Get current configuration from device"""
        config = self.duthost.shell("sonic-cfggen -d --print-data")
        pytest_assert(not config['rc'], "Failed to get configuration")
        return json.loads(config['stdout'])

    def create_tmp_config(self, config_data):
        """Create temporary config file with given data"""
        tmp_file = generate_tmpfile(self.duthost)
        self.tmp_files.append(tmp_file)
        self.duthost.copy(content=json.dumps(config_data, indent=4), dest=tmp_file)
        return tmp_file

    def verify_config_table(self, table_name, expected_data):
        """Verify if table configuration matches expected data"""
        current_config = self.get_current_config()
        current_table_config = current_config.get(table_name, {})
        pytest_assert(current_table_config == expected_data,
                      f"Configuration mismatch for {table_name}")

    def test_config_replace_single_table(self):
        """
        Test config replace with single table modification
        """
        current_config = self.get_initial_config()

        # Modify VLAN configuration
        current_config["VLAN"] = {
            f"Vlan{TEST_VLAN_ID}": {
                "admin_status": "up",
                "description": "Test_VLAN"
            }
        }

        tmp_config = self.create_tmp_config(current_config)
        output = self.duthost.shell(f"config replace {tmp_config}")
        pytest_assert(not output['rc'], "Config replace failed")

        # Verify VLAN configuration
        self.verify_config_table("VLAN", current_config["VLAN"])

    def test_config_replace_multiple_tables(self):
        """
        Test config replace with multiple table modifications
        """
        current_config = self.get_initial_config()

        # Modify multiple tables
        current_config["SYSLOG_SERVER"] = {
            TEST_SYSLOG_SERVER: {}
        }
        current_config["NTP_SERVER"] = {
            TEST_NTP_SERVER: {}
        }
        current_config["TACPLUS_SERVER"] = {
            TEST_TACACS_SERVER: {
                "priority": "1",
                "tcp_port": "49"
            }
        }

        tmp_config = self.create_tmp_config(current_config)
        output = self.duthost.shell(f"config replace {tmp_config}")
        pytest_assert(not output['rc'], "Config replace failed")

        # Verify all modified tables
        for table in ["SYSLOG_SERVER", "NTP_SERVER", "TACPLUS_SERVER"]:
            self.verify_config_table(table, current_config[table])

    def test_config_replace_invalid_config(self):
        """
        Test config replace with invalid configuration
        """
        current_config = self.get_initial_config()

        # Add invalid VLAN configuration
        current_config["VLAN"] = {
            "Vlan5000": {}  # Invalid VLAN ID
        }

        tmp_config = self.create_tmp_config(current_config)
        output = self.duthost.shell(f"config replace {tmp_config}", module_ignore_errors=True)
        pytest_assert(output['rc'] != 0, "Config replace should fail with invalid config")

    def test_config_replace_with_checkpoint(self):
        """
        Test config replace with checkpoint functionality
        """
        current_config = self.get_initial_config()

        # Modify PORTCHANNEL configuration
        current_config["PORTCHANNEL"] = {
            TEST_PORTCHANNEL: {
                "admin_status": "up",
                "mtu": "9100"
            }
        }

        # Apply initial config and create checkpoint
        tmp_initial = self.create_tmp_config(current_config)
        self.duthost.shell(f"config replace {tmp_initial}")
        checkpoint_name = "test_checkpoint"
        create_checkpoint(self.duthost, checkpoint_name)

        # Modify PORTCHANNEL configuration again
        current_config["PORTCHANNEL"] = {
            TEST_PORTCHANNEL: {
                "admin_status": "down",
                "mtu": "1500"
            }
        }

        tmp_new = self.create_tmp_config(current_config)
        self.duthost.shell(f"config replace {tmp_new}")

        # Verify new config is applied
        self.verify_config_table("PORTCHANNEL", current_config["PORTCHANNEL"])

        # Restore from checkpoint
        self.duthost.shell(f"config rollback {checkpoint_name}")

        # Verify original config is restored
        self.verify_config_table("PORTCHANNEL", {
            TEST_PORTCHANNEL: {
                "admin_status": "up",
                "mtu": "9100"
            }
        })

        # Cleanup checkpoint
        delete_checkpoint(self.duthost, checkpoint_name)

    def test_config_replace_reload_persistence(self):
        """
        Test config replace changes persist after config reload
        """
        current_config = self.get_initial_config()

        # Modify SYSLOG_SERVER configuration
        current_config["SYSLOG_SERVER"] = {
            TEST_SYSLOG_SERVER: {}
        }

        tmp_config = self.create_tmp_config(current_config)
        self.duthost.shell(f"config replace {tmp_config}")

        # Save config and reload
        self.duthost.shell("config save -y")
        self.duthost.shell("config reload -y")

        # Verify configuration persists
        self.verify_config_table("SYSLOG_SERVER", current_config["SYSLOG_SERVER"])

    def test_config_replace_partial_failure_rollback(self):
        """
        Test config replace rolls back on partial failure
        """
        current_config = self.get_initial_config()

        # Add valid VLAN and invalid PORTCHANNEL
        current_config["VLAN"] = {
            f"Vlan{TEST_VLAN_ID}": {
                "admin_status": "up"
            }
        }
        current_config["PORTCHANNEL"] = {
            "InvalidPortChannel": {}  # Invalid name
        }

        tmp_config = self.create_tmp_config(current_config)
        output = self.duthost.shell(f"config replace {tmp_config}", module_ignore_errors=True)
        pytest_assert(output['rc'] != 0, "Config replace should fail")

        # Verify VLAN was not created (rollback happened)
        self.verify_config_table("VLAN", {})

    def test_config_replace_dry_run(self):
        """
        Test config replace with --dry-run option to verify:
        1. Configuration is not actually applied
        2. The command output shows expected changes
        """
        current_config = self.get_initial_config()
        initial_config = current_config.copy()

        # Modify VLAN configuration
        current_config["VLAN"] = {
            f"Vlan{TEST_VLAN_ID}": {
                "admin_status": "up",
                "description": "Test_VLAN_DryRun"
            }
        }

        # Apply with dry-run
        tmp_config = self.create_tmp_config(current_config)
        output = self.duthost.shell(f"config replace {tmp_config} --dry-run")
        pytest_assert(not output['rc'], "Config replace dry-run failed")

        # Verify the command output indicates changes would be made
        pytest_assert("Test_VLAN_DryRun" in output['stdout'],
                      "Dry-run output should show proposed changes")

        # Verify configuration was not actually changed
        final_config = self.get_current_config()
        pytest_assert(final_config == initial_config,
                      "Configuration should not change in dry-run mode")

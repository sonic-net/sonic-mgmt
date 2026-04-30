import logging
import pytest

from tests.common.devices.oir_robot import RobotHost
from tests.common.platform.interface_utils import get_pport_presence_data

logger = logging.getLogger(__name__)

INSERT_REMOVE_RETRY_ATTEMPT_COUNT = 3


class PhysicalOir:
    def __init__(self, duthost, ansible_adhoc, port_attributes_dict):
        # Currently only automated OIR using robot is supported
        oir_attributes = next(iter(port_attributes_dict.values()))["PHYSICAL_OIR_ATTRIBUTES"]
        ports_under_test = oir_attributes["ports_under_test"]
        oir_method = oir_attributes.get("oir_method", "").lower()

        if oir_method == "automated":
            self.robot = RobotHost(duthost, ansible_adhoc, port_attributes_dict)
            self.duthost = duthost
            self.port_attributes_dict = port_attributes_dict
            self.ports_under_test = ports_under_test
        elif oir_method == "manual":
            pytest.skip("Manual OIR is not supported.")
        else:
            pytest.fail(f"OIR method '{oir_method}' is invalid.")

    def is_available(self) -> bool:
        return (self.robot.robot_hostname is not None) and (self.robot.test_cli())

    def _perform_oir_operation(self, oir_operation: str) -> None:
        """Helper method to perform OIR operations (insert or remove SFPs)."""
        if not self.robot.get_node_status():
            self.robot.start_nodes()

        for port in self.ports_under_test:
            for i in range(INSERT_REMOVE_RETRY_ATTEMPT_COUNT):
                pport_presence_data = get_pport_presence_data(self.duthost)
                port_present = pport_presence_data.get(port)

                if oir_operation == "insert":
                    if port_present:
                        logger.info(f"SFP already present in port {port}, skipping insertion.")
                        break
                    else:
                        logger.info(f"Trying to {oir_operation} SFP on port {port} - Attempt {i}")
                        result = self.robot.plug_in_one(port)
                        logger.info(f"{oir_operation.capitalize()} operation result: {result}")

                elif oir_operation == "remove":
                    if not port_present:
                        logger.info(f"SFP already not present in port {port}, skipping removal.")
                        break
                    else:
                        logger.info(f"Trying to {oir_operation} SFP on port {port} - Attempt {i}")
                        result = self.robot.unplug_one(port)
                        logger.info(f"{oir_operation.capitalize()} operation result: {result}")

    def insert_sfps(self):
        self._perform_oir_operation("insert")

    def remove_sfps(self):
        self._perform_oir_operation("remove")

    def cleanup(self):
        self.robot.stop_nodes()

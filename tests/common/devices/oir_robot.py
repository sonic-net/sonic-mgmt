import logging
import time
from typing import List

from tests.common.devices.base import AnsibleHostBase

logger = logging.getLogger(__name__)

# This module is adapted from original robot.py from Networking-scripts-libs
# https://msazure.visualstudio.com/One/_git/Networking-scripts-lib?path=%2Fapproved-internal-libraries%2Flib%2Fpython%2Fpackages%2Fstarlab-3po%2Fstarlab_3po%2Frobot_3po%2Frobot.py

CHECK_OPERATION_STATUS_DELAY = 10
THREEPO_ROBOT_CLI = "python3.12 /usr/share/test3PO/3po_robot.py {}"  # Ansible does not take aliased commands
UNPLUG_ALL = "unplug_all"
PLUG_IN_ALL = "plug_in_all"
UNPLUG_ONE = "unplug_one {}"
PLUG_IN_ONE = "plug_in_one {}"
GET_OPERATION_STATUS = "get_operation_status"
GET_ROBOT_STATUS = "get_status"
START_NODES = "start_nodes"
STOP_NODES = "stop_nodes"
NODE_STATUS = "node_status"
TEST_CLI = "test_cli"
NODE_STARTUP_SLEEP_TIME_SEC = 60


class RobotHost(AnsibleHostBase):
    """
    :summary: Class for 3PO Robot Server Host.

    Instance of this class can run ansible modules on the 3PO Robot Server Host.
    """

    def __init__(self, duthost, ansible_adhoc, port_attributes_dict):
        oir_attributes = next(iter(port_attributes_dict.values()))["PHYSICAL_OIR_ATTRIBUTES"]
        physical_oir_timeout_min = oir_attributes.get("physical_oir_timeout_min", 30)

        self.duthost = duthost
        self.tbinfo = duthost.duthosts.tbinfo
        self.robot_hostname = self.tbinfo.get("robot_server", None)
        self.robot_id = self.tbinfo.get("robot_id", None)
        self.check_operation_status_attempts = physical_oir_timeout_min * 60 // CHECK_OPERATION_STATUS_DELAY
        if self.robot_hostname and self.robot_id:
            AnsibleHostBase.__init__(self, ansible_adhoc, self.robot_hostname)
        else:
            logger.error("Either robot server or robot id is not defined in the testbed. Initialization failed.")
            raise ValueError("Robot server or robot id is missing.")

    def run_3po_robot_command(self, command: str, exp_output: List[int]) -> int:
        """
        Run the requested command on the server. allows for basic output validation
        :param command: 3po_robot command to run on server
        :param exp_output: List of acceptable server outputs
        :return: integer represent result of api call
        """

        robot_command = f"--robot {self.robot_id} {command}"
        cmd = THREEPO_ROBOT_CLI.format(robot_command)
        server_out = self.command(cmd)['stdout'].strip()
        if not server_out.isnumeric() or int(server_out) not in exp_output:
            msg = f"Cmd {cmd} received unexpected response {server_out}"
            logger.error(msg)
            raise ValueError(msg)

        return int(server_out)

    def wait_for_robot_enabled(self) -> None:
        """
        Wait for robot to show enabled. Should be called before any operation that requires robot movement
        :return: None if robot is enabled, but will raise an exception if it timesout
        """
        logger.info("Waiting for Robot to be Enabled")
        for attempt in range(self.check_operation_status_attempts):
            robot_status = self.get_robot_status()
            logger.info(f"Checking robot status : {'Enabled' if robot_status else 'Disabled'} : Check {attempt}")
            if robot_status:
                logger.info("Robot now reports being ENABLED")
                return
            logger.info("Robot still DISABLED. Waiting for retry...")
            time.sleep(CHECK_OPERATION_STATUS_DELAY)
        msg = "Robot never became ENABLED"
        logger.error(msg)
        raise Exception(msg)

    def wait_for_operation_to_complete(self) -> bool:
        """
        Wait for the active operation to complete
        Server Outputs:
        0 - indicates failure
        1 - indicates operation in progress
        2 - indicates operation is complete
        3 - indicates robot is idling, should only be true at init
        """
        log_map = {0: "Failure", 1: "In Progress", 2: "Complete", 3: "Idling"}
        # Enforces delay between operation request and status check
        # Gives time to move off of idle state
        time.sleep(5)
        logger.info("Waiting for current operation to complete")
        for attempt in range(self.check_operation_status_attempts):
            result = self.run_3po_robot_command(GET_OPERATION_STATUS, [0, 1, 2, 3])

            logger.info(f"Getting current operation status : {log_map[result]} : Check {attempt}")
            robot_status = self.get_robot_status()
            if not robot_status:
                msg = "Robot is disabled. Retry may be required"
                logger.error(msg)
                return False
            if result == 0:
                msg = "Failed to check operation status. Check server logs."
                logger.error(msg)
                return False
            if result == 2:
                logger.info("active operation was completed")
                return True
            if result == 3:
                msg = "Robot was found in idle status. This should only be possible at init"
                logger.info(msg)
                return False
            time.sleep(CHECK_OPERATION_STATUS_DELAY)

        total_time = self.check_operation_status_attempts * CHECK_OPERATION_STATUS_DELAY
        msg = f"Operation failed to complete in {total_time} seconds. Robot may be stuck."
        logger.error(msg)
        return False

    def _run_oir_operation(self, command: str, index: int = None, operation_name: str = "") -> bool:
        """
        Generic OIR operation handler
        :param command: 3po_robot command to run
        :param index: optional transceiver index
        :param operation_name: descriptive name of the operation for logging
        :return: True if operation succeeded, False otherwise
        """
        self.wait_for_robot_enabled()
        cmd = command.format(index) if index is not None else command
        result = self.run_3po_robot_command(cmd, [0, 1])
        if result == 0:
            msg = f"Failed to {operation_name}. Check server logs."
            logger.error(msg)
            return False
        logger.info(f"Successfully requested to {operation_name}... Waiting for operation complete... ")
        oper_result = self.wait_for_operation_to_complete()
        logger.info(f"{operation_name.capitalize()} completed: {oper_result}")
        return oper_result

    def unplug_all(self) -> bool:
        """
        Unplug all transceivers on network device
        Server Outputs:
        0 - indicates failure
        1 - indicates success
        """
        return self._run_oir_operation(UNPLUG_ALL, operation_name="unseat all transceivers")

    def plug_in_all(self) -> bool:
        """
        Plug in all transceivers on network device
        Server Outputs:
        0 - indicates failure
        1 - indicates success
        """
        return self._run_oir_operation(PLUG_IN_ALL, operation_name="seat all transceivers")

    def unplug_one(self, index: int) -> bool:
        """
        Unplug a specified transceiver on network device
        :param index: index for transceiver to unplug
        Server Outputs:
        0 - indicates failure
        1 - indicates success
        """
        return self._run_oir_operation(UNPLUG_ONE, index=index, operation_name=f"unseat transceiver {index}")

    def plug_in_one(self, index: int) -> bool:
        """
        Plug in a specified transceiver on network device
        :param index: index for transceiver to plug in
        Server Outputs:
        0 - indicates failure
        1 - indicates success
        """
        return self._run_oir_operation(PLUG_IN_ONE, index=index, operation_name=f"seat transceiver {index}")

    def get_robot_status(self) -> bool:
        """
        Get Robot Status
        :return: True is robot is healthy, False otherwise
        Server Outputs:
        0 - indicates failure
        1 - indicates bad robot status
        2 - indicates good robot status
        """
        result = self.run_3po_robot_command(GET_ROBOT_STATUS, [0, 1, 2])
        if result == 0:
            msg = "Failed to get robot status. Check server logs."
            logger.error(msg)
            return False
        return result != 1

    def start_nodes(self) -> None:
        """
        Start ROS nodes on robot
        Server Outputs:
        0 - indicates failure
        1 - indicates success
        """
        logger.info("Starting ros nodes on robot")
        result = self.run_3po_robot_command(START_NODES, [0, 1])
        if result == 0:
            msg = "Failed to start nodes. Check server logs."
            logger.error(msg)
            raise Exception(msg)
        logger.info("Successfully started nodes")
        time.sleep(NODE_STARTUP_SLEEP_TIME_SEC)

    def stop_nodes(self) -> None:
        """
        Stop ROS nodes on robot
        Server Outputs:
        0 - indicates failure
        1 - indicates success
        """
        logger.info("Stopping ros nodes on robot")
        result = self.run_3po_robot_command(STOP_NODES, [0, 1])
        if result == 0:
            msg = "Failed to stop nodes. Check server logs."
            logger.error(msg)
            raise Exception(msg)
        logger.info("Successfully stopped nodes")

    def get_node_status(self) -> bool:
        """
        Get whether nodes are active on robot
        Server Outputs:
        0 - indicates no nodes on robot
        1 - indicates nodes are active
        """
        logger.info("Getting node status")
        result = self.run_3po_robot_command(NODE_STATUS, [0, 1])
        if result == 0:
            return False
        logger.info("Nodes are running.")
        return True

    def test_cli(self) -> bool:
        """
        Test CLI command to verify connectivity
        Server Outputs: 1 - indicates success, failure otherwise
        """
        logger.info("Testing CLI connectivity")
        result = self.command(THREEPO_ROBOT_CLI.format(TEST_CLI))['stdout'].strip()
        logger.info(f"CLI Test Result: {result}")
        return result == "1"

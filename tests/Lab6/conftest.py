import logging
import pytest
import utils

logger = logging.getLogger()


# Fixture to measure the execution time
@pytest.fixture(scope="session")
def timing_fixture(request):
    start_time = time.time()
    yield
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info("{} took {:.5f} seconds to execute".format(request.fixturename, execution_time))


@pytest.fixture(scope="session")
def setup_interface_ip(duthost):
    utils.MEM_LIST = []
    add_command = "sudo config interface ip add Ethernet0 {}/{}".format(utils.GATEWAY_IP, utils.SUBNET_MASK)
    duthost.shell(add_command)
    memory_command = "free -h"
    res_dict = duthost.shell(memory_command)
    lines_str = "\n".join(res_dict["stdout_lines"])
    utils.MEM_LIST.append("Memory BEFORE running: \n" + lines_str)
    yield
    remove_command = "sudo config interface ip remove Ethernet0 {}/{}".format(utils.GATEWAY_IP, utils.SUBNET_MASK)
    duthost.shell(remove_command)
    res_dict = duthost.shell(memory_command)
    lines_str = "\n".join(res_dict["stdout_lines"])
    utils.MEM_LIST.append("Memory AFTER running: \n" + lines_str)
    for elem in utils.MEM_LIST:
        logger.info(elem)

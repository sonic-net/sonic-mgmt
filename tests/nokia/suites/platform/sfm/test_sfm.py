import pytest
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.platform_tests.cli.test_show_chassis_module import parse_chassis_module
from tests.platform_tests.cli.util import get_skip_mod_list


pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('ndk')
]

sfm_asic_dict = {
    "1": [0, 1],
    "2": [2, 3],
    "3": [4, 5],
    "4": [6, 7],
    "5": [8, 9],
    "6": [10, 11],
    "7": [12, 13],
    "8": [14, 15]
}
list_fab_down = list()
fab_connected = list()
all_sfm_down = False
def sfm_to_slot_map(suphost):
    exp_headers = ["Name", "Description", "Physical-Slot", "Oper-Status", "Admin-Status"]
    skip_mod_list = get_skip_mod_list(suphost)
    cmd = "show chassis modules status"
    output = suphost.shell(cmd)
    parsed_res = parse_chassis_module(output['stdout_lines'],exp_headers)
    for mod_idx in parsed_res.keys():
        if mod_idx not in skip_mod_list:
            if "FABRIC-CARD" in mod_idx:
                if parsed_res[mod_idx]['Oper-Status'] == "Online":
                    if "SFM{}".format(parsed_res[mod_idx]['Physical-Slot']) not in fab_connected:
                        fab_connected.append("SFM{}".format(parsed_res[mod_idx]['Physical-Slot']))
    logging.info("SFM connected: {}, len: {}".format(fab_connected, len(fab_connected)))
    return parsed_res


def sfm_shut_startup(suphost, operation, sfm_slot):
    if operation == "shutdown":
        cmd = "nokia_cmd set shutdown-sfm {}".format(sfm_slot)
        suphost.shell(cmd)
        logging.info("Shutdown of SFM{}".format(sfm_slot))
    elif operation == "startup":
        cmd = "nokia_cmd set startup-sfm {}".format(sfm_slot)
        suphost.shell(cmd)
        logging.info("startup of SFM{}".format(sfm_slot))


def test_sfm(duthosts, enum_supervisor_dut_hostname):
    res = {}
    suphost = duthosts[enum_supervisor_dut_hostname]
    skip_mod_list = get_skip_mod_list(suphost)
    res = sfm_to_slot_map(suphost)
    try:
        for mod_idx in res.keys():
            if mod_idx not in skip_mod_list:
                if "FABRIC-CARD" in mod_idx:
                    sfm_shut_startup(suphost, "shutdown", res[mod_idx]['Physical-Slot'])
                    pytest_assert(wait_until(60, 5, 0, sfm_status_checker, suphost, "shutdown", mod_idx),
                                  "sfm_status_check of 'Oper-Status=EMPTY' not successful for SFM {}".format(res[mod_idx]['Physical-Slot']))
                    pytest_assert(wait_until(60, 5, 0, docker_checker, suphost, "shutdown", res, mod_idx),
                                  "docker_check of 'status=EXITED' not successful for SFM{}".format(res[mod_idx]['Physical-Slot']))
                    pytest_assert(wait_until(60, 5, 0, ibgp_connectivity, duthosts),
                                  "When ALL SFM's DOWN, IBGP UP/ When some SFM's UP, IBGP DOWN ".format(res[mod_idx]['Physical-Slot']))
                    pytest_assert(wait_until(60, 5, 0, sfilink_status_checker, duthosts),
                                  "When ALL SFM's DOWN, some sfilinks UP/ When some SFM's UP, all sfilinks DOWN")

    finally:
        logging.info("test end starts")
        for mod_idx in res.keys():
            if mod_idx not in skip_mod_list:
                if "FABRIC-CARD" in mod_idx:
                    sfm_shut_startup(suphost, "startup", res[mod_idx]['Physical-Slot'])
                    sfm_status_check = wait_until(60, 5, 0, sfm_status_checker, suphost, "startup", mod_idx)
                    if sfm_status_check == False:
                        logging.info("sfm_status_check == False")
                    docker_check = wait_until(60, 5, 0, docker_checker, suphost, "startup", res, mod_idx)
                    if docker_check == False:
                        logging.info("docker_check == False")
                    ibgp_check = wait_until(60, 5, 0, ibgp_connectivity, duthosts)
                    if ibgp_check == False:
                        logging.info("ibgp_check == False")
                    sfilink_check = wait_until(60, 5, 0, sfilink_status_checker, duthosts)
                    if sfilink_check == False:
                        logging.info("sfilink_check == False")


def sfm_status_checker(suphost, operation, mod_idx):
    result = sfm_to_slot_map(suphost)
    logging.info("Checking status of SFM{}".format(result[mod_idx]['Physical-Slot']))
    if operation == "shutdown":
        if result[mod_idx]['Oper-Status'] == "Empty":
            logging.info("SFM{}  shutdown successfully".format(result[mod_idx]['Physical-Slot']))
            if "SFM{}".format(result[mod_idx]['Physical-Slot']) not in list_fab_down:
                list_fab_down.append("SFM{}".format(result[mod_idx]['Physical-Slot']))
            return True
    elif operation == "startup":
        if result[mod_idx]['Oper-Status'] == "Online":
            logging.info("SFM{}  startup successfully".format(result[mod_idx]['Physical-Slot']))
            list_fab_down.remove("SFM{}".format(result[mod_idx]['Physical-Slot']))
            return True
    else:
        logging.info("SFM{} did not {} properly".format(result[mod_idx]['Physical-Slot']), operation)
        return False
    logging.info("SFM down: {}, len_down: {}, SFM connected: {}, len_conn:{}".format(list_fab_down, len(list_fab_down), fab_connected, len(fab_connected)))


def docker_checker(suphost, operation, res, mod_idx):
    logging.info("Checking dockers syncd and swss of SFM{}".format(res[mod_idx]['Physical-Slot']))
    container_num = sfm_asic_dict[res[mod_idx]['Physical-Slot']]
    if operation == "shutdown":
        cmd = "docker ps -af 'status=exited' -af 'name=swss{0}' -af 'name=swss{1}' -af 'name=syncd{0}' -af 'name=syncd{1}'".format(container_num[0], container_num[1])
        output = suphost.shell(cmd)
        if "swss{}".format(container_num[0]) in output['stdout'] and "swss{}".format(container_num[1]) in output['stdout'] and "syncd{}".format(container_num[0]) in output['stdout'] and "syncd{}".format(container_num[1]) in output['stdout']:
            logging.info("docker swss and syncd{},{} {} successfully after SFM{} {}".format(container_num[0],container_num[1], operation,
                                                                            res[mod_idx]['Physical-Slot'], operation))
            return True
        else:
            logging.info("dockers not shutdown successfully")
    elif operation == "startup":
        cmd = "docker ps -af 'status=running' -af 'name=swss{0}' -af 'name=swss{1}' -af 'name=syncd{0}' -af 'name=syncd{1}'".format(container_num[0], container_num[1])
        output = suphost.shell(cmd)
        if "swss{}".format(container_num[0]) in output['stdout'] and "swss{}".format(container_num[1]) in output['stdout'] and "syncd{}".format(container_num[0]) in output['stdout'] and "syncd{}".format(container_num[1]) in output['stdout']:
            logging.info("docker swss and syncd{},{} {} successfully after SFM{} {}".format(container_num[0],container_num[1], operation,
                                                                            res[mod_idx]['Physical-Slot'], operation))
            return True
        else:
            logging.info("dockers not startup successfully")
            return False

    logging.info("docker checker end")


def ibgp_connectivity(duthosts):
    logging.info("Checking ibgp")
    first_frontend_node = duthosts.frontend_nodes[0]
    first_asic = first_frontend_node.asics[0]
    asic_facts = first_asic.config_facts(source="running")['ansible_facts']
    voq_nbrs = asic_facts.get('BGP_VOQ_CHASSIS_NEIGHBOR', {})
    for nbr in voq_nbrs.keys():
        if nbr.find(":") == -1:
            cmd = "sudo ip netns exec asic{} ping -c 5 {} -w 2".format(first_asic.asic_index, nbr)
            output = first_frontend_node.shell(cmd, module_ignore_errors=True)
            if "0% packet loss" not in output['stdout_lines'][-2]:
                if len(list_fab_down) == len(fab_connected):
                    logging.info("All SFM's are DOWN: 'status=EMPTY', and IBGP connectivity DOWN, as expected")
                    logging.info("SFM down: {}, len_down: {}, SFM connected: {}, len_conn:{}".format(list_fab_down, len(list_fab_down), fab_connected, len(fab_connected)))
                    return True
                else:
                    logging.info("NOT All SFM's are DOWN: 'status=EMPTY', but IBGP connectivity DOWN, NOT expected")
                    logging.info("SFM down: {}, len_down: {}, SFM connected: {}, len_conn:{}".format(list_fab_down, len(list_fab_down), fab_connected, len(fab_connected)))
                    return False

            else:
                if len(list_fab_down) < len(fab_connected):
                    logging.info("NOT All SFM's are DOWN: 'status=EMPTY', and IBGP connectivity UP, as expected. ASIC: {}, nbr: {}".format(first_asic.asic_index, nbr))
                    logging.info("SFM down: {}, len_down: {}, SFM connected: {}, len_conn:{}".format(list_fab_down, len(list_fab_down), fab_connected, len(fab_connected)))
                    return True
                else:
                    logging.info("ALL SFM's DOWN: 'status=EMPTY', but IBGP connectivity UP, not expected")
                    logging.info("SFM down: {}, len_down: {}, SFM connected: {}, len_conn:{}".format(list_fab_down,
                                                                                                     len(list_fab_down),
                                                                                                     fab_connected,
                                                                                                     len(fab_connected)))
                    return False
    logging.info("ibgp connectivity check completed")


def sfilink_status_checker(duthosts):
    logging.info("Verifying if all SFILINKS are down, when all SFM's are down ")
    for duthost in duthosts.frontend_nodes:
        for asic in duthost.asics:
            cmd = "bcmcmd -n {} 'port status' | grep sfi".format(asic.asic_index)
            output = duthost.shell(cmd)
            len_sfi = len(output['stdout_lines'])
            cmd = "bcmcmd -n {} 'port status' | grep sfi | grep -v up".format(asic.asic_index)
            output = duthost.shell(cmd)
            if len(output['stdout_lines']) == len_sfi:
                if len(list_fab_down) == len(fab_connected):
                    logging.info("all SFM's down, all sfilink port status: down")
                    logging.info("SFM down: {}, len_down: {}, SFM connected: {}, len_conn:{}".format(list_fab_down,
                                                                                                     len(list_fab_down),
                                                                                                     fab_connected,
                                                                                                     len(fab_connected)))
                    return True
                else:
                    logging.error("some SFM's up, but all sfilinks are down")
                    logging.info("SFM down: {}, len_down: {}, SFM connected: {}, len_conn:{}".format(list_fab_down,
                                                                                                     len(list_fab_down),
                                                                                                     fab_connected,
                                                                                                     len(fab_connected)))
                    return False
            else:
                if len(list_fab_down) < len(fab_connected):
                    logging.info("some SFM's and its sfilinks are up")
                    logging.info("SFM down: {}, len_down: {}, SFM connected: {}, len_conn:{}".format(list_fab_down,
                                                                                                     len(list_fab_down),
                                                                                                     fab_connected,
                                                                                                     len(fab_connected)))
                    return True
                else:
                    logging.info("some sfilinks are up even when all sfm's are down")
                    logging.info("SFM down: {}, len_down: {}, SFM connected: {}, len_conn:{}".format(list_fab_down,
                                                                                                     len(list_fab_down),
                                                                                                     fab_connected,
                                                                                                     len(fab_connected)))
                    return False



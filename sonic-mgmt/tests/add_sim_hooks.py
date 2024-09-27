#!/usr/bin/python
"""
This script adds simulation hooks/patches for test scripts.
Usage:
    python add_sim_hooks.py [--acl_counters <bool>] [--everflow_acl <bool>] [--cmds_delay <bool>] [--ignore_msgs <bool>]
Options:
    --acl_counters <bool>      Disable ACL counter sanity check until the counter issue is resolved. Default is True.
    --everflow_acl <bool>      Remove ACL table for EVERFLOW and EVERFLOWV6 to release TCAM resources. Default is True.
    --cmds_delay <bool>        Enable delay for sonic commands execution on sim, to ensure the programming is completed 
        before the next steps of the tests. Default is True. The sim related delay is defined in tests/common/devices/cisco_sim.py
    --ignore_msgs <bool>       Add ignore messages for loganalyzer specific to sim. Default is True.
"""
"""
To run tests with simulation hooks/patches, follow the steps below:
- add any required delays in common/devices/cisco_sim.py
- apply the simulation hooks/patches by running the script: 'python add_sim_hooks.py'
- add conditional skips for sim into common/plugins/conditional_mark/tests_mark_conditions_cisco_sim.yaml
- run the tests while passing the condition checks for simulation hooks/patches using the following command:
./run_scripts.py -s run_list.txt -v DT -l DT -d churchill-mono -g docker-ptf   --mark-conditions-files common/plugins/conditional_mark/tests_mark_conditions.yaml,common/plugins/conditional_mark/tests_mark_conditions_cisco_sim.yaml -c

Note: run_list.txt is a file that contains the tests to be run.
"""

import argparse
import os

ALLURE_SERVER_HOST, ALLURE_DIR = 'streams-allure-reports.cisco.com', '/tmp/allure_results'
ALLURE_REPORT_URL_FILE = 'allure_report_url.log'

def _create_parser():
    parser = argparse.ArgumentParser(description='Add simulation hooks/patches for test scripts.')
    parser.add_argument('--acl_counters', type=bool, default=True, help='Disable ACL counter sanity check until the counter issue is resolved',
                      required=False)
    parser.add_argument('--everflow_acl', type=bool, default=True, help='Remove ACL table for EVERFLOW and EVERFLOWV6 to release TCAM resources',
                      required=False)
    parser.add_argument('--cmds_delay', type=bool, default=True, help='Enable delay for sonic commands execution on sim, to ensure the programming is completed before the next steps of the tests',
                      required=False)
    parser.add_argument('--ignore_msgs', type=bool, default=True, help='Add ignore messages for loganalyzer sepcefic to sim',
                      required=False)
    
    return parser



def main():
    argparser = _create_parser()
    args = vars(argparser.parse_args())
    disable_acl_counter = args['acl_counters']
    rem_eveflow_tables = args['everflow_acl']
    add_cmds_delay = args['cmds_delay']
    add_ignore_msgs = args['ignore_msgs']
    if add_ignore_msgs:
        print("Adding ignore messages for loganalyzer related to simulation")
        append_file('../ansible/roles/test/files/tools/loganalyzer/loganalyzer_common_ignore.txt',sim_ignore_messages)
    if disable_acl_counter or rem_eveflow_tables:
        print("Adding simulation hooks/patches to remove ACL tables for EVERFLOW and EVERFLOWV6")
        append_file('acl/conftest.py', acl_conftest_patch)
    if disable_acl_counter:
        print("Disabling ACL counter sanity check until the counter issue is resolved")
        disable_fixures('acl/test_acl.py','@pytest.yield_fixture', 'counters_sanity_check')
        decorate_function('acl/custom_acl_table/test_custom_acl_table.py', 'def test_custom_acl(', ['@pytest.mark.skip_traffic_test'])
    if rem_eveflow_tables:
        print("Hooking ACL table removal for EVERFLOW and EVERFLOWV6")
        disable_fixures('acl/test_acl.py', '@pytest.fixture','remove_dataacl_table')
        disable_fixures('acl/test_stress_acl.py', '@pytest.fixture','remove_dataacl_table')
        disable_fixures('acl/test_acl_outer_vlan.py', '@pytest.fixture','remove_dataacl_table')
    if add_cmds_delay:
        print("Adding delay for sonic commands execution on sim, the details are defined in tests/common/devices/cisco_sim.py")
        dec_lines=["from tests.common.devices.cisco_sim import sim_conditional_delay","@sim_conditional_delay"]
        decorate_function('common/devices/base.py', 'def _run(self, *module_args, **complex_args):', dec_lines)

def disable_fixures(file, fixure, function_name):
    with open(file, 'r') as f:
        lines = f.readlines()
    with open(file, 'w') as f:
        for i, line in enumerate(lines):
            if i>=len(lines)-1:
                f.write(line)
                break
            if fixure in line and function_name in lines[i+1]:
                line = line.replace(fixure, "#"+fixure)
            f.write(line)

def append_file(file, content):
    with open(file, 'a') as f:
        sim_hook_sign = '## added by sim hook ##' + os.linesep
        f.write(sim_hook_sign+content)

def decorate_function(file, function_name, dec_lines):
    with open(file) as f:
        lines = f.readlines()
    updated_lines = []
    for line in lines:
        if function_name in line:
            leading_whitespace = line[:len(line) - len(line.lstrip())]
            for l in dec_lines:
                updated_lines.append(leading_whitespace + l + os.linesep)
        updated_lines.append(line)
    with open(file, 'w') as f:
        for line in updated_lines:
            f.write(line)


sim_ignore_messages = '''
r, ".* ERR syncd#syncd#syncd:.*Leaba_Err: Entry requested not found.*"
r, ".* ERR syncd#syncd#syncd:.*check_reset_allowed: CRIT mac port SerDes.*",
r, ".* ERR syncd#syncd#syncd:.*SAI_LOG.*src/sai_trap.cpp:.*: Invalid trap event code.*"
r, ".* ERR syncd#syncd#syncd:.*SAI_LOG|SAI_API_FDB: Incorrect BRIDGE PORT ID, event: SAI_FDB_EVENT_AGED.*"
r, ".* ERR syncd#syncd#syncd:.*SAI_LOG|SAI_API_FDB: Can not get bridge or vlan, event: SAI_FDB_EVENT_AGED.*"
r, ".* ERR syncd#syncd#syncd:.*destroy API returned: status = Leaba_Err: Resource needed for operation is busy.*" 
r, ".* ERR swss#orchagent: :- doCfgSensorsTableTask: ASIC sensors : unsupported operation.*"
r, ".* ERR syncd#syncd#syncd: :- process_on_fdb_event: invalid OIDs in fdb notifications, NOT translating and NOT storing in ASIC DB.*"
r, ".* ERR pmon#xcvrd.*CMIS:.*no suitable app for the port appl.*"
r, ".* ERR pmon#xcvrd.*: CMIS: Ethernet.*: FAILED.*"
r, ".* ERR syncd#syncd#syncd:.*shared/src/hld/npu/la_svi_port_base.cpp:.*Leaba_Err: Entry requested not found.*",
r, ".* ERR syncd#syncd#syncd: :- process_on_fdb_event: FDB notification was not sent since it contain invalid OIDs.*"
'''

acl_conftest_patch = '''
import logging
from tests.common.config_reload import config_reload
logger = logging.getLogger(__name__)

@pytest.yield_fixture(scope="module", autouse=True)
def counters_sanity_check():
    logger.info("Skip check for ACL counter for simulation ")
    rule_list = []
    yield rule_list
    return

## sim hook ##
@pytest.fixture(scope="module", autouse=True)
def remove_dataacl_table(duthosts):
    """
    Remove DATAACL to free TCAM resources.
    The change is written to configdb as we don't want DATAACL recovered after reboot
    """
    TABLE_NAME = "DATAACL"
    for duthost in duthosts:
        lines = duthost.shell(cmd="show acl table {}".format(TABLE_NAME))['stdout_lines']
        data_acl_existing = False
        for line in lines:
            if TABLE_NAME in line:
                data_acl_existing = True
                break
        if data_acl_existing:
            # Remove DATAACL
            logger.info("Removing ACL table {}".format(TABLE_NAME))
            cmds = [
                "config acl remove table {}".format(TABLE_NAME),
                "config acl remove table EVERFLOWV6",
                "config acl remove table EVERFLOW",
                "config save -y"
            ]
        else:
            cmds = [
                "config acl remove table EVERFLOWV6",
                "config acl remove table EVERFLOW",
                "config save -y"
            ]
        duthost.shell_cmds(cmds=cmds)
    yield
    # Recover DUT by reloading minigraph
    for duthost in duthosts:
        config_reload(duthost, config_source="minigraph")

'''


if __name__ == '__main__':
  main()
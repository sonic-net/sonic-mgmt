import os
import pytest
import random
import logging

from copy import deepcopy
from jinja2 import Template
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from swan_agent_helpers import get_swan_agent_file


logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.swanagent_required,
    pytest.mark.topology('wan-com'),
]

SONIC_SWAN_FILE_PATH = '/tmp'
DEVICE_NAME = 'DeviceName="vlab-01"'
WAN_PUB_FIB_PROGRAM_TEMPLATE = 'wan/isis/swan_agent/template/wan_pub_fib_program.j2'
LOAD_COMMAND = 'curl -v -i http://localhost:10000/flowtable -H "Content-Type:text/xml" --data @{}'

params_group = {
    "DeviceName_1":
    {
        "DeviceName_1_1": DEVICE_NAME,
        "DeviceName_1_2": DEVICE_NAME,
        "DeviceName_1_3": DEVICE_NAME,
        "DeviceName_1_4": DEVICE_NAME
    },
    "DeviceName_2":
    {
        "DeviceName_2_1": DEVICE_NAME
    },
    "Family_1":
    {
        "Family_1_1": 'Family="ResolveIP"',
        "Family_1_2": 'Family="MplsIngress"'
    },
    "Family_2":
    {
        "Family_2_1": 'Family="Ipv6"',
        "Family_2_2": 'Family="Ipv4"'
    },
    "Label_1":
    {
        "Label_1_1": 'Label="24896"'
    },
    "Label_2":
    {
        "Label_2_1": 'Label="0"',
        "Label_2_2": 'Label="34006"',
        "Label_2_3": 'Label="0"',
        "Label_2_4": 'Label="34007"'
    },
    "GroupId":
    {
        "GroupId_1": 'GroupId="IBR01.PHX10-to-LAX_GW_Mplsv4_0"',
        "GroupId_2": 'GroupId="IBR01.PHX10-to-LAX_GW_Mplsv4_0"'
    },
    "EgressIpv4":
    {
        "EgressIpv4_1": 'EgressIpv4="100.1.0.29"',
        "EgressIpv4_2": 'EgressIpv4="100.1.0.30"',
        "EgressIpv4_3": 'EgressIpv4="100.1.0.29"',
        "EgressIpv4_4": 'EgressIpv4="100.1.0.30"'
    },
    "Interface":
    {
        "Interface_1": 'Interface="PortChannel101"',
        "Interface_2": 'Interface="PortChannel102"',
        "Interface_3": 'Interface="PortChannel101"',
        "Interface_4": 'Interface="PortChannel102"'
    },
    "NhopIpv4":
    {
        "NhopIpv4_1": 'NhopIpv4="10.0.0.57"',
        "NhopIpv4_2": 'NhopIpv4="10.0.0.59"',
        "NhopIpv4_3": 'NhopIpv4="10.0.0.57"',
        "NhopIpv4_4": 'NhopIpv4="10.0.0.59"'
    }
}

valid_params = {
    "DeviceName": ["vlab-01"],
    "Family_1":  ["ResolveIP", "MplsIngress"],
    "Family_2": ["Ipv6", "Ipv4"],
    "Label_1": ["24896"],
    "Label_2": ["0", "34006", "34007"],
    "GroupId": ["IBR01.PHX10-to-LAX_GW_Mplsv4_0"],
    "EgressIpv4": ["100.1.0.29", "100.1.0.30"],
    "Interface": ["PortChannel101", "PortChannel102"],
    "NhopIpv4": ["10.0.0.57", "10.0.0.59"]
}

invalid_params = {
    "DeviceName_1": ["sonic", "arista", "ibr"],
    "DeviceName_2": ["sonic", "arista", "ibr"],
    "Family_1":  ["ResoIP", "Mplress"],
    "Family_2": ["Ipv", "Iv4"],
    "Label_1": ["3406200000"],
    "Label_2": ["3406200000"],
    # "GroupId": ["IBR01.PHX10-to-LAX_GW_Mplsv4_0"],
    "EgressIpv4": ["100.1.0", "00.1.0.30", "100.2.2.10"],
    "Interface": ["PortChannel1", "PortChannel1020"],
    "NhopIpv4": ["10.0.0", "00.0.0.59", "10.1.1.1"]
}

missing_prompt = {
    "DeviceName_1": "forwarding table DeviceName is empty",
    "DeviceName_2": "group table DeviceName is empty",
    "EgressIpv4": "error parsing empty egress IP",
    "Family_1": "forwarding table Family:  is not valid",
    "Family_2": "forwarding table Family:  is not valid",
    "GroupId": "error group does not exist",
    "Interface": "error parsing empty nexthop interface",
    "Label_1" : "error parsing label",
    "Label_2" : "attribute Labels not present for ActionType PUSH_LABEL in FIB",
    "NhopIpv4" : "error parsing empty nexthop IP"
}


@pytest.fixture(scope="function", autouse=True)
def check_swan_agent_state(duthost):
    output = duthost.shell('curl http://localhost:10000/version')['stdout_lines']
    regex_ver = re.compile(r'(\S+)-(\S+-\S+).x64.tar')
    pytest_assert(output[0] == regex_ver.match(get_swan_agent_file()).group(2),
                  'Failed to load swan agent')


def load_parameters(params):
    param_dict = {}
    for k, v in params.items():
        param_dict.update(v)
    return param_dict


def combine_params(param_key, param_value):
    regex_prefix = re.compile(r'([A-Za-z0-9]+)(_\d)?')
    prefix = regex_prefix.match(param_key).group(1)
    return '{}=\"{}\"'.format(prefix, param_value)


def import_xml_to_swan_agent(dut_host, template_vars, case_name):
    swan_template = Template(open(WAN_PUB_FIB_PROGRAM_TEMPLATE).read())
    dest_file = os.path.join(SONIC_SWAN_FILE_PATH, case_name) + ".xml"
    dut_host.copy(content = swan_template.render(load_parameters(template_vars)), dest=dest_file)
    load_cmd = LOAD_COMMAND.format(dest_file)
    return dut_host.shell(load_cmd)['stdout_lines']


def test_swan_correct_xml(swan_agent_setup_teardown, request):
    dut_host = swan_agent_setup_teardown
    output = import_xml_to_swan_agent(dut_host, params_group, request.node.name)

    pytest_assert(output[0] == "HTTP/1.1 200 OK",
                'Fail to load {}.xml to swan agent'.format(request.node.name))
    
    groupId = valid_params['GroupId'][0]

    # 1. check groupid exist in swan agent tunnels
    output = dut_host.shell("curl http://localhost:10000/tunnels")['stdout']
    pytest_assert(groupId in output, 'Fail to find GroupId: {} in swan agent tunnels'.format(groupId))

    # 2. check groupid exist in redis NEXTHOP_GROUP_TABLE
    output = dut_host.shell("redis-cli -n 0 KEYS NEXTHOP_GROUP_TABLE*")['stdout']
    pytest_assert(groupId in output, 'Fail to find GroupId: {} in redis NEXTHOP_GROUP_TABLE'.format(groupId))

    # 3. check incoming label exist in redis LABEL_ROUTE_TABLE
    output = dut_host.shell("redis-cli -n 0 KEYS LABEL_ROUTE_TABLE*")['stdout']
    for label in valid_params["Label_1"]:
        pytest_assert("LABEL_ROUTE_TABLE:{}".format(label) in output,
                    'Fail to find incoming label: {} in redis LABEL_ROUTE_TABLE'.format(label))

    # 4. check groupid exist in redis CLASS_BASED_NEXT_HOP_GROUP_TABLE
    output = dut_host.shell("redis-cli -n 0 KEYS CLASS_BASED_NEXT_HOP_GROUP_TABLE*")['stdout']
    pytest_assert(groupId in output, 'Fail to find GroupId: {} in redis NEXTHOP_GROUP_TABLE'.format(groupId))


@pytest.mark.parametrize("target_field", params_group.keys())
def test_swan_xml_missing_1_field(swan_agent_setup_teardown, request, target_field, capsys):
    dut_host = swan_agent_setup_teardown
    target_params = deepcopy(params_group)
    selected_key = random.choice(target_params[target_field].keys())
    target_params[target_field].pop(selected_key)

    # with capsys.disabled():
    #     print("selected_key: {}".format(selected_key))

    output = import_xml_to_swan_agent(dut_host, target_params, request.node.name)
    pytest_assert(output[0] == "HTTP/1.1 400 Bad Request",
                'Load error {}.xml to swan agent'.format(request.node.name))

    pytest_assert(missing_prompt[target_field] in output[-1],
                'Not find prompt {} for missing {}'.format(missing_prompt[target_field], target_field))


@pytest.mark.parametrize("target_field", params_group.keys())
def test_swan_xml_missing_x_field(swan_agent_setup_teardown, request, target_field, capsys):
    dut_host = swan_agent_setup_teardown
    target_params = deepcopy(params_group)
    selected_keys = random.sample(target_params[target_field].keys(),
                random.randint(1, len(target_params[target_field].keys())))
    for key in selected_keys:
        target_params[target_field].pop(key)
        # with capsys.disabled():
        #     print("selected_key: {}".format(key))

    output = import_xml_to_swan_agent(dut_host, target_params, request.node.name)
    pytest_assert(output[0] == "HTTP/1.1 400 Bad Request",
                'Load error {}.xml to swan agent'.format(request.node.name))

    pytest_assert(missing_prompt[target_field] in output[-1],
                'Not find prompt {} for missing {}'.format(missing_prompt[target_field], target_field))


def invalid_field_prompt(target_field, value):
    if target_field == "DeviceName_1":
        return "forwarding table DeviceName: {} does not match Host: vlab-01".format(value)
    elif target_field == "DeviceName_2":
        return "group table DeviceName: {} does not match Host: vlab-01".format(value)
    elif target_field == "EgressIpv4":
        return "error parsing egress IP {}".format(value)
    elif target_field == "Family_1" or target_field == "Family_2":
        return "forwarding table Family: {} is not valid".format(value)
    elif target_field == "NhopIpv4":
        return "error parsing nexthop IP {}".format(value)


@pytest.mark.parametrize("target_field", invalid_params.keys())
def test_swan_xml_wrong_field(swan_agent_setup_teardown, request, target_field, capsys):
    dut_host = swan_agent_setup_teardown
    target_params = deepcopy(params_group)

    value = random.choice(invalid_params[target_field])
    index = random.randint(1, len(target_params[target_field].keys()))

    for value in invalid_params[target_field]:
        for index in range(1, len(target_params[target_field].keys())+1):
            target_params[target_field]['{}_{}'.format(target_field, index)] = combine_params(target_field, value)

            output = import_xml_to_swan_agent(dut_host, target_params, request.node.name)
            # with capsys.disabled():
            #     print("index: {}, value: {}".format(index, value))
            #     print("output: {}".format(output[-1]))
            #     print("expected: {}".format(invalid_field_prompt(target_field, value)))
            pytest_assert(output[0] == "HTTP/1.1 400 Bad Request",
                        'Load error {}.xml to swan agent'.format(request.node.name))

            pytest_assert(output[-1] in invalid_field_prompt(target_field, value),
                        'Not find prompt {} for invalid {}'.format(invalid_params[target_field], target_field))
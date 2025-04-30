import os
import tempfile
import json
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.gu_utils import delete_tmpfile, expect_op_success, generate_tmpfile
from tests.common.gu_utils import apply_patch
from tests.generic_config_updater.add_cluster.helpers import add_content_to_patch_file, add_static_route, \
    change_interface_admin_state_for_namespace, clear_static_route, get_cfg_info_from_dut, \
    get_exabgp_port_for_neighbor, remove_dataacl_table_single_dut, remove_static_route, \
    send_and_verify_traffic, verify_routev4_existence

pytestmark = [
        pytest.mark.topology("t2")
        ]

logger = logging.getLogger(__name__)


# -----------------------------
# Attributes used by test for static route, acl config
# -----------------------------

EXABGP_BASE_PORT = 5000
NHIPV4 = '10.10.246.254'
STATIC_DST_IP = '192.162.0.128'

ACL_TABLE_NAME = "L3_TRANSPORT_TEST"
ACL_TABLE_STAGE_EGRESS = "egress"
ACL_TABLE_TYPE_L3 = "L3"
ACL_RULE_FILE_PATH = "generic_config_updater/add_cluster/acl/acl_rule_src_dst_port.json"
ACL_RULE_DST_FILE = "/tmp/test_add_cluster_acl_rule.json"
ACL_RULE_SKIP_VERIFICATION_LIST = [""]


# -----------------------------
# Helper functions that validate apply-patch changes
# -----------------------------

def verify_bgp_peers_removed_from_asic(duthost, namespace):
    logger.info("{}: Verifying bgp_neighbors info is removed.".format(duthost.hostname))
    cur_bgp_neighbors = get_cfg_info_from_dut(duthost, "BGP_NEIGHBOR", namespace)
    cur_device_neighbor = get_cfg_info_from_dut(duthost, "DEVICE_NEIGHBOR", namespace)
    cur_device_neighbor_metadata = get_cfg_info_from_dut(duthost, "DEVICE_NEIGHBOR_METADATA", namespace)
    pytest_assert(not cur_bgp_neighbors,
                  "Bgp neighbors info removal via apply-patch failed."
                  )
    pytest_assert(not cur_device_neighbor,
                  "Device neighbor info removal via apply-patch failed."
                  )
    pytest_assert(not cur_device_neighbor_metadata,
                  "Device neighbor metadata info removal via apply-patch failed."
                  )


# -----------------------------
# Helper functions that modify configuration via apply-patch
# -----------------------------

def apply_patch_remove_cluster(config_facts,
                               config_facts_localhost,
                               mg_facts,
                               duthost,
                               enum_rand_one_asic_namespace,
                               scenario='standalone'):
    """
    Wrapper function that removes cluster for a specific namespace.

    This function takes as input the initial config facts that contain information about interfaces and neighbors
    for the selected namespace and constructs the paths to remove.

    The configuration changes include:
    - Removing BGP neighbors for the interfaces of the namespace
    - Shutting down local interfaces
    - Removing interfaces for the namespace

    This configuration is achieved using separate functions that construct the relevant JSON files used in apply-patch.
    Based on the tested scenario (attribute `scenario`, possible values: ['standalone', 'aggregated']),
    the configuration can be applied gradually by running apply-patch at each step,
    or all at once using a single JSON file and a single run of the apply-patch command.
    """

    logger.info("Removing cluster for namespace {} via apply-patch.".format(enum_rand_one_asic_namespace))
    patch_file = ""
    if scenario == 'standalone':
        apply = True
        verify = True
    else:
        apply = False
        verify = False
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            patch_file = temp_file.name

    # removing bgp neighbors for namespace
    remove_neighbors_for_namespace(config_facts,
                                   duthost,
                                   enum_rand_one_asic_namespace,
                                   apply=apply,
                                   patch_file=patch_file,
                                   verify=verify)

    # shutdown interfaces for namespace
    change_interface_admin_state_for_namespace(config_facts,
                                               duthost,
                                               enum_rand_one_asic_namespace,
                                               status='down',
                                               apply=apply,
                                               patch_file=patch_file,
                                               verify=verify)
    # remove interfaces for namespace
    remove_interfaces_for_namespace(config_facts,
                                    config_facts_localhost,
                                    duthost,
                                    enum_rand_one_asic_namespace,
                                    mg_facts['minigraph_port_name_to_alias_map'],
                                    apply=apply,
                                    patch_file=patch_file,
                                    verify=verify)
    # in case of aggregated scenario, apply all the above changes via single-file apply-patch
    if scenario != "standalone":
        with open(patch_file, "r") as file:
            aggregated_json_data = json.load(file)

        tmpfile = generate_tmpfile(duthost)

        try:
            output = apply_patch(duthost, json_data=aggregated_json_data, dest_file=tmpfile)
            expect_op_success(duthost, output)
        finally:
            delete_tmpfile(duthost, tmpfile)
            if os.path.exists(patch_file):
                os.remove(patch_file)


def apply_patch_add_cluster(config_facts,
                            config_facts_localhost,
                            mg_facts,
                            duthost,
                            enum_rand_one_asic_namespace,
                            scenario='standalone'):
    """
    Wrapper function that adds cluster for a specific namespace.

    This function takes as input the initial config facts that contain information about interfaces and neighbors
    for the selected namespace and re-applies the same configuration that was previously removed.

    The configuration added includes:
    - Configuring local interfaces for the namespace
    - Starting up local interfaces
    - Adding BGP neighbors for the newly added interfaces

    This configuration is achieved using separate functions that construct the relevant JSON files used in apply-patch.
    Based on the tested scenario (attribute `scenario`, possible values: ['standalone', 'aggregated']),
    the configuration can be applied gradually by running apply-patch at each step,
    or all at once using a single JSON file and a single run of the apply-patch command.
    """

    logger.info("Adding cluster for namespace {} via apply-patch.".format(enum_rand_one_asic_namespace))
    patch_file = ""
    if scenario == 'standalone':
        apply = True
        verify = True
    else:
        apply = False
        verify = False
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            patch_file = temp_file.name

    # adding interfaces for namespace
    add_interfaces_for_namespace(config_facts,
                                 config_facts_localhost,
                                 duthost,
                                 enum_rand_one_asic_namespace,
                                 mg_facts['minigraph_port_name_to_alias_map'],
                                 apply=apply,
                                 patch_file=patch_file,
                                 verify=verify)
    # startup interfaces for namespace
    change_interface_admin_state_for_namespace(config_facts,
                                               duthost,
                                               enum_rand_one_asic_namespace,
                                               status='up',
                                               apply=apply,
                                               patch_file=patch_file,
                                               verify=verify)
    # adding bgp neighbors for namespace
    add_neighbors_for_namespace(config_facts,
                                duthost,
                                enum_rand_one_asic_namespace,
                                apply=apply,
                                patch_file=patch_file,
                                verify=verify)
    # in case of aggregated scenario, apply all the above changes via single-file apply-patch
    if scenario != "standalone":
        with open(patch_file, "r") as file:
            aggregated_json_data = json.load(file)

        tmpfile = generate_tmpfile(duthost)

        try:
            output = apply_patch(duthost, json_data=aggregated_json_data, dest_file=tmpfile)
            expect_op_success(duthost, output)
        finally:
            delete_tmpfile(duthost, tmpfile)
            if os.path.exists(patch_file):
                os.remove(patch_file)


def remove_neighbors_for_namespace(cfgfacts,
                                   duthost,
                                   namespace,
                                   apply=True,
                                   verify=True,
                                   patch_file=""):
    """
    Applies a patch to remove neighbors configuration for a specific namespace on the DUT host.

    Applies changes at configuration paths:
        - /<namespace>/BGP_NEIGHBOR
        - /<namespace>/DEVICE_NEIGHBOR
        - /<namespace>/DEVICE_NEIGHBOR_METADATA
        - /localhost/BGP_NEIGHBOR
        - /localhost/DEVICE_NEIGHBOR_METADATA

    This function modifies the DUT host's configuration by removing the neighbors configuration for the given
    namespace using an apply-patch approach. Optionally, it can verify the changes after patching.
    """

    logger.info("{}: Removing BGP peers for ASIC namespace {}".format(duthost.hostname, namespace))
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch_asic = []
    json_patch_localhost = []

    json_patch_asic = [
        {
            "op": "remove",
            "path": "{}/BGP_NEIGHBOR".format(json_namespace)
        },
        {
            "op": "remove",
            "path": "{}/DEVICE_NEIGHBOR".format(json_namespace)
        },
        {
            "op": "remove",
            "path": "{}/DEVICE_NEIGHBOR_METADATA".format(json_namespace)
        }
    ]

    # identify the keys to remove
    bgp_neighbor_dict = cfgfacts["BGP_NEIGHBOR"]
    device_neighbor_metadata_dict = cfgfacts["DEVICE_NEIGHBOR_METADATA"]
    paths_list = []
    paths_to_remove = ["/localhost/BGP_NEIGHBOR/",
                       "/localhost/DEVICE_NEIGHBOR_METADATA/"]
    keys_to_remove = [
        bgp_neighbor_dict.keys() if bgp_neighbor_dict else [],
        device_neighbor_metadata_dict.keys() if device_neighbor_metadata_dict else []
    ]
    for path, keys in zip(paths_to_remove, keys_to_remove):
        for k in keys:
            paths_list.append(path + k)
    for path in paths_list:
        json_patch_localhost.append({
            "op": "remove",
            "path": path
        })

    # combine localhost and ASIC patch data
    json_patch = json_patch_localhost + json_patch_asic

    if apply:
        tmpfile = generate_tmpfile(duthost)
        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(duthost, output)
            if verify is True:
                verify_bgp_peers_removed_from_asic(duthost, namespace)
        finally:
            delete_tmpfile(duthost, tmpfile)
    else:
        add_content_to_patch_file(json.dumps(json_patch, indent=4), patch_file)


def remove_interfaces_for_namespace(config_facts,
                                    config_facts_localhost,
                                    duthost,
                                    namespace,
                                    port_to_alias_dict,
                                    apply=True,
                                    verify=True,
                                    patch_file=""):
    """
    Applies a patch to remove interfaces for a specific namespace on the DUT host.

    This function removes the specified interfaces from the provided namespace on the DUT host by applying a patch.
    The patch will use a mapping of port names to aliases,
    which is used to remove interfaces information from localhost namespace,
    and an optional verification step can be performed after the removal.

    Applies changes at configuration paths:
    - /<namespace>/PORTCHANNEL_MEMBER
    - /<namespace>/PORTCHANNEL_INTERFACE
    - /<namespace>/INTERFACE
    - /<namespace>/PORT
    - /localhost/INTERFACE
    - /localhost/PORTCHANNEL_INTERFACE
    - /localhost/PORTCHANNEL_MEMBER
    """

    logger.info("{}: Removing local interfaces for ASIC namespace {}".format(duthost.hostname, namespace))
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch_asic = [
        {
            "op": "remove",
            "path": "{}/PORTCHANNEL_MEMBER".format(json_namespace)
        },
        {
            "op": "remove",
            "path": "{}/PORTCHANNEL_INTERFACE".format(json_namespace)
        },
        {
            "op": "remove",
            "path": "{}/INTERFACE".format(json_namespace)
        }
    ]
    json_patch_localhost = []
    # in localhost replace the interface name with the interface alias
    interface_dict = config_facts["INTERFACE"]
    port_keys = []
    localhost_interface_keys = []
    for key, _value in interface_dict.items():
        if key.startswith('Ethernet-Rec'):
            continue
        parts = key.split('|')
        key_to_remove = key
        if len(parts) == 2:
            port = parts[0]
            alias = port_to_alias_dict.get(port, port)
            key_to_remove = "{}|{}".format(alias, parts[1])
        else:
            key_to_remove = port_to_alias_dict.get(key, key)
        key_to_remove = key_to_remove.replace("/", "~1")
        localhost_interface_keys.append(key_to_remove)
        port_keys.append(key)
    # construct portchannel keys
    portchannel_keys = config_facts["PORTCHANNEL_INTERFACE"].keys()
    localhost_portchannel_member_dict = config_facts_localhost["PORTCHANNEL_MEMBER"]
    localhost_portchannel_member_keys = []
    for portchannel in portchannel_keys:
        if portchannel in localhost_portchannel_member_dict:
            for key, _value in localhost_portchannel_member_dict[portchannel].items():
                key_to_remove = portchannel + '|' + key.replace("/", "~1")
                localhost_portchannel_member_keys.append(key_to_remove)
    localhost_portchannel_interface_dict = config_facts_localhost["PORTCHANNEL_INTERFACE"]
    localhost_portchannel_interface_keys = []
    for portchannel in portchannel_keys:
        if portchannel in localhost_portchannel_interface_dict:
            localhost_portchannel_interface_keys.append(portchannel)
            for key, _value in localhost_portchannel_interface_dict[portchannel].items():
                key_to_remove = portchannel + '|' + key.replace("/", "~1")
                localhost_portchannel_interface_keys.append(key_to_remove)

    # construct all paths
    paths_list = []
    paths_to_remove = ["{}/PORT/".format(json_namespace),
                       "/localhost/INTERFACE/",
                       "/localhost/PORTCHANNEL_INTERFACE/",
                       "/localhost/PORTCHANNEL_MEMBER/"]
    keys_to_remove = [
        localhost_interface_keys,
        localhost_portchannel_interface_keys,
        localhost_portchannel_member_keys,
    ]
    for path, keys in zip(paths_to_remove, keys_to_remove):
        for k in keys:
            paths_list.append(path + k)
    for path in paths_list:
        json_patch_localhost.append({
            "op": "remove",
            "path": path
        })

    # Combine localhost and ASIC patch data
    # Until Issue sonic-buildimage/issues/20377 is resolved the removal of the interfaces will be done only for
    # asic namespace. Localhost will retain information on interfaces mapping
    # json_patch = json_patch_localhost + json_patch_asic
    json_patch = json_patch_asic

    if apply:

        tmpfile = generate_tmpfile(duthost)

        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(duthost, output)
            if verify is True:
                logger.info("{}: Verifying interfaces info is removed.".format(duthost.hostname))
                interface_dict = get_cfg_info_from_dut(duthost, "INTERFACE", namespace)
                portchannel_interface_dict = get_cfg_info_from_dut(duthost, "PORTCHANNEL_INTERFACE", namespace)
                portchannel_member_dict = get_cfg_info_from_dut(duthost, "PORTCHANNEL_MEMBER", namespace)
                pytest_assert(not interface_dict,
                              "Interfaces info removal via apply-patch failed.")
                pytest_assert(not portchannel_interface_dict,
                              "Portchannel interfaces info removal via apply-patch failed.")
                pytest_assert(not portchannel_member_dict,
                              "Portchannel members info removal via apply-patch failed.")
        finally:
            delete_tmpfile(duthost, tmpfile)
    else:
        add_content_to_patch_file(json.dumps(json_patch, indent=4), patch_file)


def add_neighbors_for_namespace(cfgfacts,
                                duthost,
                                namespace,
                                apply=True,
                                verify=True,
                                patch_file=""):
    """
    Applies a patch to add BGP neighbors for a specific namespace on the DUT host that had been previously removed from
    function 'apply_patch_remove_neighbors_for_namespace'.

    This function adds the necessary BGP neighbors to the provided namespace on the DUT host by applying a patch.
    It uses the configuration facts to re-add same neighbors as before
    and can optionally verify the changes after the neighbors are added.
    """

    bgp_neighbor_dict = cfgfacts["BGP_NEIGHBOR"]
    device_neighbor_dict = cfgfacts["DEVICE_NEIGHBOR"]
    device_neighbor_metadata_dict = cfgfacts["DEVICE_NEIGHBOR_METADATA"]
    logger.info("{}: Adding back BGP peers for asic namespace {}".format(duthost.hostname, namespace))
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch_asic = [
        {
            "op": "add",
            "path": "{}/BGP_NEIGHBOR".format(json_namespace),
            "value": bgp_neighbor_dict
        },
        {
            "op": "add",
            "path": "{}/DEVICE_NEIGHBOR".format(json_namespace),
            "value": device_neighbor_dict
        },
        {
            "op": "add",
            "path": "{}/DEVICE_NEIGHBOR_METADATA".format(json_namespace),
            "value": device_neighbor_metadata_dict
        }
    ]

    json_patch_localhost = []
    # identify the keys to add
    add_paths_list = []
    add_values_list = []
    for k, v in list(bgp_neighbor_dict.items()):
        add_paths_list.append('/localhost/BGP_NEIGHBOR/{}'.format(k))
        add_values_list.append(v)
    for k, v in list(device_neighbor_dict.items()):
        add_paths_list.append('/localhost/DEVICE_NEIGHBOR/{}'.format(k))
        add_values_list.append(v)
    for k, v in list(device_neighbor_metadata_dict.items()):
        add_paths_list.append('/localhost/DEVICE_NEIGHBOR_METADATA/{}'.format(k))
        add_values_list.append(v)
    for path, value in zip(add_paths_list, add_values_list):
        json_patch_localhost.append({
            "op": "add",
            "path": path,
            "value": value
        })

    # combine localhost and ASIC patch data
    json_patch = json_patch_localhost + json_patch_asic

    if apply:

        tmpfile = generate_tmpfile(duthost)
        logger.info("tmpfile {}".format(tmpfile))
        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(duthost, output)
            if verify is True:
                logger.info("{}: Verifying bgp_neighbors info is added back.".format(duthost.hostname))
                bgp_neighbors = get_cfg_info_from_dut(duthost, "BGP_NEIGHBOR", namespace)
                device_neighbor = get_cfg_info_from_dut(duthost, "DEVICE_NEIGHBOR", namespace)
                device_neighbor_metadata = get_cfg_info_from_dut(duthost, "DEVICE_NEIGHBOR_METADATA", namespace)
                # Wait until bgp sessions are established on DUT
                pytest_assert(wait_until(100, 10, 0, duthost.check_bgp_session_state,
                                         list(
                                             bgp_neighbors.keys()
                                             )), "Not all BGP sessions are established on \
                                                DUT after adding them via apply-patch")

                pytest_assert(bgp_neighbors == bgp_neighbor_dict,
                              "Not all Bgp neighbors are added via apply-patch.")
                pytest_assert(device_neighbor == device_neighbor_dict,
                              "Not all Device neighbor data are added via apply-patch.")
                pytest_assert(device_neighbor_metadata == device_neighbor_metadata_dict,
                              "Not all Device neighbor metadata are added via apply-patch.")
        finally:
            delete_tmpfile(duthost, tmpfile)
    else:
        add_content_to_patch_file(json.dumps(json_patch, indent=4), patch_file)


def format_sonic_interface_dict(interface_dict, single_entry=True):
    """
    Converts a SONiC interface dictionary into the correct format so the formatted value can be used
    as the 'value' in a JSON patch.

    - Ensures interfaces exist as standalone keys.
    - Converts IP addresses into the "Interface|IP" format.
    """
    formatted_interface_dict = {}

    for key, values in interface_dict.items():
        if isinstance(values, dict):  # if IPs are defined under the interface
            if single_entry:
                formatted_interface_dict[key] = {}
            for ip in values.keys():
                formatted_interface_dict[f"{key}|{ip}"] = {}
        else:
            if single_entry:
                formatted_interface_dict[key] = {}

    return formatted_interface_dict


def add_interfaces_for_namespace(config_facts,
                                 config_facts_localhost,
                                 duthost,
                                 namespace,
                                 port_to_alias_dict,
                                 apply=True,
                                 verify=True,
                                 patch_file=""):
    """
    Applies a patch to add network interfaces for a specific namespace on the DUT host that had been previously removed
    from function 'apply_patch_remove_interfaces_for_namespace'.

    This function adds network interfaces to the provided namespace by applying a patch on the DUT host.
    It utilizes the configuration facts from both the DUT and the localhost,
    that contains interfaces information before the removal, and can optionally verify the changes
    after the interfaces are added.
    """

    interface_dict = format_sonic_interface_dict(config_facts["INTERFACE"])
    portchannel_interface_dict = format_sonic_interface_dict(config_facts["PORTCHANNEL_INTERFACE"])
    portchannel_member_dict = format_sonic_interface_dict(config_facts["PORTCHANNEL_MEMBER"], single_entry=False)

    logger.info("{}: Adding back interfaces for asic namespace {}".format(duthost.hostname, namespace))
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch_asic = [
        {
            "op": "add",
            "path": "{}/INTERFACE".format(json_namespace),
            "value": interface_dict
        },
        {
            "op": "add",
            "path": "{}/PORTCHANNEL_INTERFACE".format(json_namespace),
            "value": portchannel_interface_dict
        },
        {
            "op": "add",
            "path": "{}/PORTCHANNEL_MEMBER".format(json_namespace),
            "value": portchannel_member_dict
        }
    ]

    json_patch_localhost = []
    # in localhost replace the interface name with the interface alias
    localhost_interface_dict = {}
    for key, value in interface_dict.items():
        if key.startswith('Ethernet-Rec'):
            continue
        parts = key.split('|')
        updated_key = key
        if len(parts) == 2:
            port = parts[0]
            alias = port_to_alias_dict.get(port, port)
            updated_key = "{}|{}".format(alias, parts[1])
        else:
            updated_key = port_to_alias_dict.get(key, key)
        updated_key = updated_key.replace("/", "~1")
        localhost_interface_dict[updated_key] = value
    # do same for portchannel_member
    localhost_portchannel_member_dict = {}
    for key, value in portchannel_member_dict.items():
        parts = key.split('|')
        updated_key = key
        if len(parts) == 2:
            port = parts[1]
            if port.startswith('Ethernet-Rec'):
                continue
            alias = port_to_alias_dict.get(port, port)
            updated_key = "{}|{}".format(parts[0], alias)
        updated_key = updated_key.replace("/", "~1")
        localhost_portchannel_member_dict[updated_key] = value

    # find the keys to add
    add_paths_list = []
    add_values_list = []
    for k, v in list(interface_dict.items()):
        key = port_to_alias_dict.get(k, k).replace("/", "~1")
        add_paths_list.append("/localhost/INTERFACE/{}".format(key))
        add_values_list.append(v)
    for k, v in list(portchannel_interface_dict.items()):
        key = port_to_alias_dict.get(k, k).replace("/", "~1")
        add_paths_list.append("/localhost/PORTCHANNEL_INTERFACE/{}".format(k))
        add_values_list.append(v)
    for k, v in list(portchannel_member_dict.items()):
        key = port_to_alias_dict.get(k, k).replace("/", "~1")
        add_paths_list.append("/localhost/PORTCHANNEL_MEMBER/{}".format(k))
        add_values_list.append(v)
    for path, value in zip(add_paths_list, add_values_list):
        json_patch_localhost.append({
            "op": "add",
            "path": path,
            "value": value
        })

    # Combine localhost and ASIC patch data
    # Until Issue sonic-buildimage/issues/20377 is resolved the removalof the interfaces will be done only for
    # asic namespace. Localhost will retain information on interfaces mapping
    # json_patch = json_patch_localhost + json_patch_asic
    json_patch = json_patch_asic

    if apply:
        tmpfile = generate_tmpfile(duthost)
        logger.info("tmpfile {}".format(tmpfile))
        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(duthost, output)
            if verify is True:
                logger.info("{}: Verifying interfaces info is added back.".format(duthost.hostname))
                cur_interface = get_cfg_info_from_dut(duthost, "INTERFACE", namespace)
                cur_portchannel_interface = get_cfg_info_from_dut(duthost, "PORTCHANNEL_INTERFACE", namespace)
                cur_portchannel_member = get_cfg_info_from_dut(duthost, "PORTCHANNEL_MEMBER", namespace)
                logger.info("Current interfaces from duthost={}".format(cur_interface))
                pytest_assert(cur_interface == interface_dict, "Not all interfaces are added via apply-patch.")
                pytest_assert(cur_portchannel_interface == portchannel_interface_dict,
                              "Not all portchannel interfaces are added via apply-patch.")
                pytest_assert(cur_portchannel_member == portchannel_member_dict,
                              "Not all portchannel members are added via apply-patch.")
        finally:
            delete_tmpfile(duthost, tmpfile)
    else:
        add_content_to_patch_file(json.dumps(json_patch, indent=4), patch_file)


# -----------------------------
# Setup Fixtures/functions
# -----------------------------

@pytest.fixture(scope="module", params=[False, True])
def acl_config_scenario(request):
    return request.param


def setup_acl_config(duthost, ip_netns_namespace_prefix):
    logger.info("Adding acl config.")
    remove_dataacl_table_single_dut("DATAACL", duthost)
    duthost.command("{} config acl add table {} {} -s {}".format(
        ip_netns_namespace_prefix, ACL_TABLE_NAME, ACL_TABLE_TYPE_L3, ACL_TABLE_STAGE_EGRESS))
    duthost.copy(src=ACL_RULE_FILE_PATH, dest=ACL_RULE_DST_FILE)
    duthost.shell("{} acl-loader update full --table_name {} {}".format(
        ip_netns_namespace_prefix, ACL_TABLE_NAME, ACL_RULE_DST_FILE))
    acl_tables = duthost.command("{} show acl table".format(ip_netns_namespace_prefix))["stdout_lines"]
    acl_rules = duthost.command("{} show acl rule".format(ip_netns_namespace_prefix))["stdout_lines"]
    logging.info(('\n'.join(acl_tables)))
    logging.info(('\n'.join(acl_rules)))


def remove_acl_config(duthost, ip_netns_namespace_prefix):
    logger.info("Removing acl config.")
    config_reload(duthost, config_source="minigraph", safe_reload=True)
    acl_tables = duthost.command("{} show acl table".format(ip_netns_namespace_prefix))["stdout_lines"]
    acl_rules = duthost.command("{} show acl rule".format(ip_netns_namespace_prefix))["stdout_lines"]
    logging.info(('\n'.join(acl_tables)))
    logging.info(('\n'.join(acl_rules)))


@pytest.fixture(scope="module")
def setup_static_route(tbinfo, duthosts, enum_downstream_dut_hostname,
                       enum_rand_one_frontend_asic_index,
                       rand_bgp_neigh_ip_name):
    duthost = duthosts[enum_downstream_dut_hostname]
    bgp_neigh_ip, bgp_neigh_name = rand_bgp_neigh_ip_name
    logger.info("Adding static route {} to be routed via bgp neigh {}.".format(STATIC_DST_IP, bgp_neigh_ip))
    exabgp_port = get_exabgp_port_for_neighbor(tbinfo, bgp_neigh_name, EXABGP_BASE_PORT)
    route_exists = verify_routev4_existence(duthost, enum_rand_one_frontend_asic_index,
                                            STATIC_DST_IP, should_exist=True)
    if route_exists:
        logger.warning("Route exists already - will try to clear")
        clear_static_route(tbinfo, duthost, STATIC_DST_IP)
    add_static_route(tbinfo, bgp_neigh_ip, exabgp_port, ip=STATIC_DST_IP, nhipv4=NHIPV4)
    wait_until(10, 1, 0, verify_routev4_existence, duthost,
               enum_rand_one_frontend_asic_index, STATIC_DST_IP, should_exist=True)

    yield

    logger.info("Removing static route {} .".format(STATIC_DST_IP))
    remove_static_route(tbinfo, bgp_neigh_ip, exabgp_port, ip=STATIC_DST_IP, nhipv4=NHIPV4)
    wait_until(10, 1, 0, verify_routev4_existence, duthost,
               enum_rand_one_frontend_asic_index, STATIC_DST_IP, should_exist=False)


@pytest.fixture(scope="function")
def initialize_random_variables(enum_downstream_dut_hostname,
                                enum_upstream_dut_hostname,
                                enum_rand_one_frontend_asic_index,
                                enum_rand_one_asic_namespace,
                                ip_netns_namespace_prefix,
                                rand_bgp_neigh_ip_name):
    return enum_downstream_dut_hostname, enum_upstream_dut_hostname, enum_rand_one_frontend_asic_index, \
        enum_rand_one_asic_namespace, ip_netns_namespace_prefix, rand_bgp_neigh_ip_name


@pytest.fixture(scope="function")
def initialize_facts(mg_facts,
                     config_facts,
                     config_facts_localhost):
    return mg_facts, config_facts, config_facts_localhost


@pytest.fixture(scope="function")
def setup_add_cluster(tbinfo,
                      duthosts,
                      initialize_random_variables,
                      initialize_facts,
                      ptfadapter,
                      apply_patch_scenario,
                      acl_config_scenario,
                      setup_static_route):
    """
    This setup fixture prepares the Downstream LC by applying a patch to remove
    and then re-add the cluster configuration.

    The purpose is to prepare the DUT host for test cases that validate functionality
    after adding a cluster via apply-patch.
    The fixture reads the running configuration and constructs patches to remove
    the current config from a running namespace.
    After verifying successful removal, it re-adds the configuration and validates that it was successfully restored.

    **Setup steps - applied to the Downstream LC:**
    1. Save the original configuration.
    2. Remove the cluster from a randomly selected namespace.
    3. Verify BGP information, route table, and interface details to ensure everything has been removed as expected.
    4. Perform data verification in the upstream → downlink direction, targeting a static route, which should now fail.
    5. Re-add the cluster to the randomly selected namespace.
    6. Verify BGP information, route table, and interface details to ensure everything is restored as expected.
    7. Add ACL configuration based on the test parameter value.

    **Teardown steps:**
    The setup logic already re-applies the initial cluster configuration for the namespace.
    The only recovery needed during teardown is for the ACL configuration:
    1. Restore the ACL configuration to its initial values.
    """

    # initial test env
    enum_downstream_dut_hostname, enum_upstream_dut_hostname, enum_rand_one_frontend_asic_index, \
        enum_rand_one_asic_namespace, ip_netns_namespace_prefix, rand_bgp_neigh_ip_name = initialize_random_variables
    mg_facts, config_facts, config_facts_localhost = initialize_facts
    duthost = duthosts[enum_downstream_dut_hostname]
    duthost_src = duthosts[enum_upstream_dut_hostname]
    asic_id = enum_rand_one_frontend_asic_index
    asic_id_src = None
    all_asic_ids = duthost_src.get_asic_ids()
    for asic in all_asic_ids:
        if duthost_src == duthost and asic == asic_id:
            continue
        asic_id_src = asic
        break
    bgp_neigh_ip, _bgp_neigh_name = rand_bgp_neigh_ip_name
    pytest_assert(
        asic_id_src is not None, "Couldn't find an asic id to be used for sending traffic. \
            Reserved asic id: {}. All available asic ids: {}".format(
            asic_id, all_asic_ids
        )
    )
    initial_buffer_pg_info = get_cfg_info_from_dut(duthost, 'BUFFER_PG', enum_rand_one_asic_namespace)

    # Removing cluster for namespace
    apply_patch_remove_cluster(config_facts,
                               config_facts_localhost,
                               mg_facts,
                               duthost,
                               enum_rand_one_asic_namespace,
                               scenario=apply_patch_scenario)

    # Verify routes removed
    wait_until(5, 1, 0, verify_routev4_existence, duthost,
               enum_rand_one_frontend_asic_index, bgp_neigh_ip, should_exist=False)
    wait_until(5, 1, 0, verify_routev4_existence, duthost,
               enum_rand_one_frontend_asic_index, STATIC_DST_IP, should_exist=False)
    # Verify buffer pg mapping after interfaces removal, profiles for these interfaces should have been auto-removed
    buffer_pg_info_remove_interfaces = get_cfg_info_from_dut(duthost, 'BUFFER_PG', enum_rand_one_asic_namespace)
    # pytest_assert(buffer_pg_info_remove_interfaces == {},
    #              "Didn't find expected BUFFER_PG info in CONFIG_DB after removing the interfaces.")
    if buffer_pg_info_remove_interfaces != {}:
        logger.warning("Didn't find expected BUFFER_PG info in CONFIG_DB after removing the interfaces.")

    # Verify traffic to static route fails
    logger.info("Data Verification after removing cluster.\
                Direction: upstream->downstream. Dst IP: Static Route {}. Expected Result: Fail".format(STATIC_DST_IP))
    send_and_verify_traffic(tbinfo, duthost_src, duthost, asic_id_src, asic_id,
                            ptfadapter, dst_ip=STATIC_DST_IP, count=10, expect_error=True)

    # Adding back cluster for namespace
    apply_patch_add_cluster(config_facts,
                            config_facts_localhost,
                            mg_facts,
                            duthost,
                            enum_rand_one_asic_namespace,
                            scenario=apply_patch_scenario)
    # Verify routes added
    wait_until(5, 1, 0, verify_routev4_existence,
               duthost, enum_rand_one_frontend_asic_index, bgp_neigh_ip, should_exist=True)
    wait_until(5, 1, 0, verify_routev4_existence,
               duthost, enum_rand_one_frontend_asic_index, STATIC_DST_IP, should_exist=True)
    # Verify buffer pg mapping after adding interfaces, updated profiles should have been auto-created
    buffer_pg_info_add_interfaces = get_cfg_info_from_dut(duthost, 'BUFFER_PG', enum_rand_one_asic_namespace)
    pytest_assert(buffer_pg_info_add_interfaces == initial_buffer_pg_info,
                  "Didn't find expected BUFFER_PG info in CONFIG_DB after adding back the interfaces.")
    if acl_config_scenario:
        setup_acl_config(duthost, ip_netns_namespace_prefix)

    yield

    if acl_config_scenario:
        remove_acl_config(duthost, ip_netns_namespace_prefix)


# -----------------------------
# Test Definitions
# -----------------------------

@pytest.mark.disable_loganalyzer
def test_add_cluster(tbinfo,
                     duthosts,
                     initialize_random_variables,
                     ptfadapter,
                     acl_config_scenario,
                     setup_add_cluster):
    """
    Validates the functionality of the Downstream Linecard after adding a cluster.

    Performs lossless data traffic scenarios for both ACL and non-ACL cases.
    Verifies successful data transmission, queue counters, and ACL rule match counters.
    """

    # initial test env
    enum_downstream_dut_hostname, enum_upstream_dut_hostname, enum_rand_one_frontend_asic_index, \
        enum_rand_one_asic_namespace, ip_netns_namespace_prefix, rand_bgp_neigh_ip_name = initialize_random_variables
    duthost = duthosts[enum_downstream_dut_hostname]
    duthost_up = duthosts[enum_upstream_dut_hostname]
    asic_id = enum_rand_one_frontend_asic_index
    asic_id_src = None
    asic_id_src_up = None
    for asic in duthost.get_asic_ids():
        if asic == asic_id:
            continue
        asic_id_src = asic
        break
    for asic in duthost_up.get_asic_ids():
        asic_id_src_up = asic
        break

    pytest_assert(
        asic_id_src is not None, "Couldn't find an asic id to be used for sending traffic. \
            Reserved asic id: {}. All available asic ids: {}".format(
            asic_id, duthost.get_asic_ids()
        )
    )
    pytest_assert(
        asic_id_src is not None, "Couldn't find an asic id to be used for sending traffic from upstream. \
            All available asic ids: {}".format(
            duthost_up.get_asic_ids()
        )
    )
    # Traffic scenarios applied in non-al, acl scenario
    traffic_scenarios = [
        {"direction": "upstream->downstream", "dst_ip": STATIC_DST_IP, "count": 10, "dscp": 3,
         "sport": 1234, "dport": 50, "verify": True, "expect_error": False},
        {"direction": "downstream->downstream", "dst_ip": STATIC_DST_IP, "count": 10, "dscp": 3,
         "sport": 1234, "dport": 50, "verify": True, "expect_error": False}
    ]
    if acl_config_scenario:
        traffic_scenarios = [
            {"direction": "upstream->downstream", "dst_ip": STATIC_DST_IP, "count": 10, "dscp": 3,
             "sport": 5000, "dport": 50, "verify": True, "expect_error": False, "match_rule": "RULE_100"},
            {"direction": "upstream->downstream", "dst_ip": STATIC_DST_IP, "count": 10, "dscp": 3,
             "sport": 1234, "dport": 8080, "verify": True, "expect_error": True, "match_rule": "RULE_200"},
            {"direction": "upstream->downstream", "dst_ip": STATIC_DST_IP, "count": 10, "dscp": 3,
             "sport": 1234, "dport": 50, "verify": True, "expect_error": False, "match_rule": None},
            {"direction": "downstream->downstream", "dst_ip": STATIC_DST_IP, "count": 10, "dscp": 3,
             "sport": 5000, "dport": 50, "verify": True, "expect_error": False, "match_rule": "RULE_100"},
            {"direction": "downstream->downstream", "dst_ip": STATIC_DST_IP, "count": 10, "dscp": 3,
             "sport": 1234, "dport": 8080, "verify": True, "expect_error": True, "match_rule": "RULE_200"},
            {"direction": "downstream->downstream", "dst_ip": STATIC_DST_IP, "count": 10, "dscp": 3,
             "sport": 1234, "dport": 50, "verify": True, "expect_error": False, "match_rule": None}
        ]

    for traffic_scenario in traffic_scenarios:
        logger.info("Starting Data Traffic Scenario: {}".format(traffic_scenario))
        if traffic_scenario["direction"] == "upstream->downstream":
            src_duthost = duthost_up
            src_asic_index = asic_id_src_up
        elif traffic_scenario["direction"] == "downstream->downstream":
            src_duthost = duthost
            src_asic_index = asic_id_src
        else:
            pytest_assert("Unsupported direction for traffic scenario {}.".format(traffic_scenario["direction"]))

        if acl_config_scenario:
            duthost.shell('{} aclshow -c'.format(ip_netns_namespace_prefix))

        send_and_verify_traffic(tbinfo, src_duthost, duthost, src_asic_index, asic_id,
                                ptfadapter,
                                dst_ip=traffic_scenario["dst_ip"],
                                dscp=traffic_scenario["dscp"],
                                count=traffic_scenario["count"],
                                sport=traffic_scenario["sport"],
                                dport=traffic_scenario["dport"],
                                verify=traffic_scenario["verify"],
                                expect_error=traffic_scenario["expect_error"])

        if acl_config_scenario:
            acl_counters = duthost.show_and_parse('{} aclshow -a'.format(ip_netns_namespace_prefix))
            for acl_counter in acl_counters:
                if acl_counter["rule name"] in ACL_RULE_SKIP_VERIFICATION_LIST:
                    continue
                pytest_assert(acl_counter["packets count"] == str(traffic_scenario["count"])
                              if acl_counter["rule name"] == traffic_scenario["match_rule"]
                              else acl_counter["packets count"] == '0',
                              "Acl rule {} statistics are not as expected. Found value {}"
                              .format(acl_counter["rule name"], acl_counter["packets count"]))

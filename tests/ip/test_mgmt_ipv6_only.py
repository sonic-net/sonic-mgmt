import pytest

from tests.common.fixtures.duthost_utils import convert_and_restore_config_db_to_ipv6_only  # noqa F401
from tests.common.helpers.assertions import pytest_assert, pytest_require

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exception(loganalyzer):
    ignore_regex = [
        # For dualtor duts, we set up mux simulator on the servers,
        # but if the server doesn't have IPv6 addr, the mux simulator is unavailable,
        # Then y cable issue is reported, since the IPv6 test only focus on the mgmt plane,
        # we can ignore this error log
        # Sample logs:

        # Mar 28 05:18:28.331508 dut INFO logrotate: Sending SIGHUP to OA log_file_name: /var/log/swss/sairedis.rec
        # Mar 28 05:18:28.459615 dut WARNING pmon#CCmisApi: y_cable_port 11: attempt=6, GET http://192.168.0.1:8082/mux/vms21-6/20 for physical_port 11 failed with URLError(timeout('timed out')) # noqa E501
        # Mar 28 05:18:28.459615 dut WARNING pmon#CCmisApi: y_cable_port 11: Retry GET http://192.168.0.1:8082/mux/vms21-6/20 for physical port 11 timeout after 30 seconds, attempted=6 # noqa E501
        # Mar 28 05:18:28.460209 dut ERR pmon#CCmisApi: Error: Could not establish the active side for Y cable port Ethernet40 to perform read_y_cable update state db # noqa E501
        # Mar 28 05:18:28.460598 dut NOTICE swss#orchagent: message repeated 2 times: [ :- start: performing log rotate]
        # Mar 28 05:18:28.460598 dut NOTICE swss#orchagent: :- addOperation: Mux setting State DB entry (hw state unknown, mux state unknown) for port Ethernet40 # noqa E501
        # Mar 28 05:18:28.461333 dut NOTICE mux#linkmgrd: MuxManager.cpp:288 addOrUpdateMuxPortMuxState: Ethernet40: state db mux state: unknown # noqa E501
        # Mar 28 05:18:28.461640 dut NOTICE mux#linkmgrd: link_manager/LinkManagerStateMachineActiveStandby.cpp:686 handleMuxStateNotification: Ethernet40: state db mux state: Unknown # noqa E501
        # Mar 28 05:18:28.462126 dut NOTICE mux#linkmgrd: link_manager/LinkManagerStateMachineActiveStandby.cpp:1297 LinkProberWaitMuxUnknownLinkUpTransitionFunction: Ethernet40 # noqa E501

        ".*ERR pmon#CCmisApi: Error: Could not establish the active side for Y cable port Ethernet[0-9]* to perform read_y_cable update state db", # noqa E501
    ]

    if loganalyzer:
        for hostname in loganalyzer.keys():
            loganalyzer[hostname].ignore_regex.extend(ignore_regex)


def test_bgp_facts_ipv6_only(duthosts, enum_frontend_dut_hostname, enum_asic_index,
                             convert_and_restore_config_db_to_ipv6_only): # noqa F811
    """compare the bgp facts between observed states and target state"""

    duthost = duthosts[enum_frontend_dut_hostname]

    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
    namespace = duthost.get_namespace_from_asic_id(enum_asic_index)
    config_facts = duthost.config_facts(host=duthost.hostname, source="running", namespace=namespace)['ansible_facts']
    sonic_db_cmd = "sonic-db-cli {}".format("-n " + namespace if namespace else "")
    for k, v in list(bgp_facts['bgp_neighbors'].items()):
        # Verify bgp sessions are established
        assert v['state'] == 'established'
        # Verify local ASNs in bgp sessions
        assert v['local AS'] == int(config_facts['DEVICE_METADATA']['localhost']['bgp_asn'].encode().decode("utf-8"))
        # Check bgpmon functionality by validate STATE DB contains this neighbor as well
        state_fact = duthost.shell('{} STATE_DB HGET "NEIGH_STATE_TABLE|{}" "state"'
                                   .format(sonic_db_cmd, k), module_ignore_errors=False)['stdout_lines']
        peer_type = duthost.shell('{} STATE_DB HGET "NEIGH_STATE_TABLE|{}" "peerType"'
                                  .format(sonic_db_cmd, k),
                                  module_ignore_errors=False)['stdout_lines']
        assert state_fact[0] == "Established"
        assert peer_type[0] == "i-BGP" if v['remote AS'] == v['local AS'] else "e-BGP"

    # In multi-asic, would have 'BGP_INTERNAL_NEIGHBORS' and possibly no 'BGP_NEIGHBOR' (ebgp) neighbors.
    nbrs_in_cfg_facts = {}
    nbrs_in_cfg_facts.update(config_facts.get('BGP_NEIGHBOR', {}))
    nbrs_in_cfg_facts.update(config_facts.get('BGP_INTERNAL_NEIGHBOR', {}))
    # In VoQ Chassis, we would have BGP_VOQ_CHASSIS_NEIGHBOR as well.
    nbrs_in_cfg_facts.update(config_facts.get('BGP_VOQ_CHASSIS_NEIGHBOR', {}))
    for k, v in list(nbrs_in_cfg_facts.items()):
        # Compare the bgp neighbors name with config db bgp neighbors name
        assert v['name'] == bgp_facts['bgp_neighbors'][k]['description']
        # Compare the bgp neighbors ASN with config db
        assert int(v['asn'].encode().decode("utf-8")) == bgp_facts['bgp_neighbors'][k]['remote AS']


def test_show_features_ipv6_only(duthosts, enum_dut_hostname, convert_and_restore_config_db_to_ipv6_only): # noqa F811
    """Verify show features command output against CONFIG_DB
    """

    duthost = duthosts[enum_dut_hostname]
    features_dict, succeeded = duthost.get_feature_status()
    pytest_assert(succeeded, "failed to obtain feature status")
    for cmd_key, cmd_value in list(features_dict.items()):
        redis_value = duthost.shell('/usr/bin/redis-cli -n 4 --raw hget "FEATURE|{}" "state"'
                                    .format(cmd_key), module_ignore_errors=False)['stdout']
        pytest_assert(redis_value.lower() == cmd_value.lower(),
                      "'{}' is '{}' which does not match with config_db".format(cmd_key, cmd_value))


def test_image_download_ipv6_only(creds, duthosts, enum_dut_hostname,
                                  convert_and_restore_config_db_to_ipv6_only): # noqa F811
    """
    Test image download in mgmt ipv6 only scenario
    """
    duthost = duthosts[enum_dut_hostname]
    image_url = creds.get("test_image_url", {}).get("ipv6", "")
    pytest_require(len(image_url) != 0, "Cannot get image url")
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    mgmt_interfaces = cfg_facts.get("MGMT_INTERFACE", {}).keys()
    for mgmt_interface in mgmt_interfaces:
        output = duthost.shell("curl --fail --interface {} {}".format(mgmt_interface, image_url),
                               module_ignore_errors=True)
        if output["rc"] == 0:
            break
    else:
        pytest.fail("Failed to download image from image_url {} via any of {}"
                    .format(image_url, list(mgmt_interfaces)))

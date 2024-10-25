import ipaddr as ipaddress
import json
import pytest
import time
from tests.common import config_reload
pytestmark = [
    pytest.mark.topology('any')
]

def test_lag_member_forwarding_packets(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    lag_facts = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']
    if not len(lag_facts['lags'].keys()):
        pytest.skip("No Lag found in this topology")
    portchannel_name = list(lag_facts['lags'].keys())[0]
    portchannel_members = list(lag_facts['lags'][portchannel_name]['po_stats']['ports'].keys())
    assert len(portchannel_members) > 0
    asic_name = lag_facts['names'][portchannel_name]
    asic_idx = duthost.get_asic_id_from_namespace(asic_name)

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_config = list(duthost.get_running_config_facts()["BGP_NEIGHBOR"].values())[0]
    holdtime = 0

    peer_device_ip_set = set()

    for peer_device_ip, peer_device_bgp_data in config_facts['BGP_NEIGHBOR'].items():
        if peer_device_bgp_data["name"] == config_facts['DEVICE_NEIGHBOR'][portchannel_members[0]]['name']:
            peer_device_ip_set.add(peer_device_ip)
            if not holdtime:
                holdtime = duthost.get_bgp_neighbor_info(peer_device_ip, asic_idx)["bgpTimerHoldTimeMsecs"]

    assert len(peer_device_ip_set) == 2
    assert holdtime > 0

    asichost = duthost.asic_instance_from_namespace(asic_name)

    bgp_fact_info = asichost.bgp_facts()

    for ip in peer_device_ip_set:
        assert bgp_fact_info['ansible_facts']['bgp_neighbors'][ip]['state'] == 'established'

    for ip in peer_device_ip_set:
        if ipaddress.IPNetwork(ip).version == 4:
            rc = asichost.ping_v4(ip)
        else:
            rc = asichost.ping_v6(ip)

        assert rc

    lag_member_file_dir = duthost.shell('mktemp')['stdout']
    lag_member_config = []
    for portchannel_member_name in portchannel_members:
        lag_member_config.append({
            "LAG_MEMBER_TABLE:{}:{}".format(portchannel_name, portchannel_member_name): {
                "status": "disabled"
            },
            "OP": "SET"
        })
    try:
        # Copy json file to DUT
        duthost.copy(content=json.dumps(lag_member_config, indent=4), dest=lag_member_file_dir, verbose=False)
        json_set = "/dev/stdin < {}".format(lag_member_file_dir)
        result = duthost.docker_exec_swssconfig(json_set, "swss", asic_idx)
        if result["rc"] != 0:
            pytest.fail(
                "Failed to apply lag member configuration file: {}".format(result["stderr"])
            )
        # make sure ping should fail
        for ip in peer_device_ip_set:
            if ipaddress.IPNetwork(ip).version == 4:
                rc = asichost.ping_v4(ip)
            else:
                rc = asichost.ping_v6(ip)

            if rc:
                pytest.fail("Ping is still working on lag disable member for neighbor {}", ip)
       
        time.sleep(holdtime/1000)
        # Make sure BGP goes down
        bgp_fact_info = asichost.bgp_facts()
        for ip in peer_device_ip_set:
            if bgp_fact_info['ansible_facts']['bgp_neighbors'][ip]['state'] == 'established':
                pytest.fail("BGP is still enable on lag disable member for neighbor {}", ip)
    finally:
        duthost.shell('rm -f {}'.format(lag_member_file_dir))
        config_reload(duthost, config_source='config_db')

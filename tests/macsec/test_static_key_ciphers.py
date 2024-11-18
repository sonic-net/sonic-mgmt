import pytest
import logging
import random
import time
import json
import os

from .macsec_config_helper import setup_macsec_configuration, cleanup_macsec_configuration

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t2"),
]


def macsec_check(host, cli_options, int, neighv4, neighv6, macsec=True, cipher=None):
    if macsec:
        # Verify Macsec Status Between Neighbors is up
        output = host.shell('sonic-cfggen{} -d -v PORT.{}'.format(cli_options, int),
                            module_ignore_errors=True)['stdout']
        logger.debug(output)
        logger.debug("'macsec': '{}'".format(cipher))
        assert "'macsec': '{}'".format(cipher) in output
        # Verify WPA Supplicant process is running on specific port
        output = host.shell('ps aux | grep "USER\\|wpa_supplicant"', module_ignore_errors=True)['stdout']
        logger.debug(output)
        assert int in output
        # Verify macsec is enabled on port and session is up and established
        output = host.shell("show macsec{} {}".format(cli_options, int), module_ignore_errors=True)
        output = output['stdout'].split("\n")
        logger.debug(output)
        assert "enable                 true" in output[3]

    # Verify BGP Between Neighbors is established
    output = host.shell("show ip bgp neighbor {}".format(neighv4))['stdout']
    logger.debug("BGP v4: {}".format(output))
    assert "BGP state = Established" in output
    output = host.shell("show ipv6 bgp neighbor {}".format(neighv6))['stdout']
    logger.debug("BGP v6: {}".format(output))
    assert "BGP state = Established" in output


def test_static_key_ciphers(duthosts, nbrhosts, request, profile_name, tbinfo, ctrl_links, rekey_period,
                            enum_rand_one_per_hwsku_frontend_hostname):
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Neighbor type must be sonic")
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']
    asic_index = random.choice(duthost.get_frontend_asic_ids())
    logger.debug(f"ASIC index: {asic_index}")
    skip_hosts = duthost.get_asic_namespace_list()
    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
    else:
        cli_options = ''
    dut_lldp_table = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()
    dut_to_neigh_int = dut_lldp_table[0]
    neigh_to_dut_int = dut_lldp_table[4]
    neigh_name = dut_lldp_table[1]
    neighhost = nbrhosts[dut_lldp_table[1]]["host"]
    if neighhost.is_multi_asic:
        neigh_cli_options = " -n " + neighhost.get_namespace_from_asic_id(neighhost.get_frontend_asic_ids())
    else:
        neigh_cli_options = ''
    logger.debug("dut cli: {} neigh cli: {}".format(cli_options, neigh_cli_options))

    int_list = {
        dut_to_neigh_int: {
            'host': neighhost,
            'port': neigh_to_dut_int
        }
    }
    time.sleep(45)

    # gather IP address information
    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][neigh_name]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][neigh_name]['bgp']['peers'][dut_asn][1].lower()
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            if v['description'] == neigh_name:
                if v['ip_version'] == 4:
                    neigh_ip_v4 = k
                elif v['ip_version'] == 6:
                    neigh_ip_v6 = k
                logger.debug(v['state'])
                assert v['state'] == 'established'

    with open(os.path.dirname(__file__) + '/profile.json') as f:
        macsec_profiles = json.load(f)

    cleanup_macsec_configuration(duthost, ctrl_links, profile_name)

    # wait to ensure link has come up with no macsec
    time.sleep(45)
    macsec_check(duthost, cli_options, dut_to_neigh_int, neigh_ip_v4, neigh_ip_v6, macsec=False)

    # use each macsec profile and verify operation
    for k, v in list(macsec_profiles.items()):
        if duthost.facts["asic_type"] == "vs" and v['send_sci'] == "false":
            # On EOS, portchannel mac is not same as the member port mac (being as SCI),
            # then src mac is not equal to SCI in its sending packet. The receiver of vSONIC
            # will drop it for macsec kernel module does not correctly handle it.
            continue
        else:
            logger.debug("k: {} v: {}".format(k, v))
            setup_macsec_configuration(duthost, int_list, k, v['priority'],
                                       v['cipher_suite'], v['primary_cak'], v['primary_ckn'], v['policy'],
                                       v['send_sci'],
                                       rekey_period)

            logger.debug("dut macsec profiles:")
            logger.debug(duthost.shell("sonic-cfggen -d --var-json MACSEC_PROFILE")['stdout'])
            logger.debug("neighbor macsec profiles:")
            logger.debug(neighhost.shell("sonic-cfggen -d --var-json MACSEC_PROFILE")['stdout'])

            # wait for BGP to come up
            time.sleep(30)
            macsec_check(duthost, cli_options, dut_to_neigh_int, neigh_ip_v4, neigh_ip_v6, cipher=k)
            macsec_check(neighhost, neigh_cli_options, neigh_to_dut_int, dut_ip_v4, dut_ip_v6, cipher=k)
            cleanup_macsec_configuration(duthost, int_list, k)
            time.sleep(30)
            macsec_check(duthost, cli_options, dut_to_neigh_int, neigh_ip_v4, neigh_ip_v6, macsec=False)

    # reenable original profile
    setup_macsec_configuration(duthost, int_list, profile_name, macsec_profiles[profile_name]['priority'],
                               macsec_profiles[profile_name]['cipher_suite'],
                               macsec_profiles[profile_name]['primary_cak'],
                               macsec_profiles[profile_name]['primary_ckn'], macsec_profiles[profile_name]['policy'],
                               macsec_profiles[profile_name]['send_sci'], rekey_period)
    logger.debug(duthost.shell("docker ps")['stdout'])
    macsec_check(duthost, cli_options, dut_to_neigh_int, neigh_ip_v4, neigh_ip_v6, cipher=profile_name)

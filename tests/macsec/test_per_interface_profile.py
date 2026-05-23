import pytest
import logging

from tests.common.utilities import wait_until
from tests.common.macsec.macsec_helper import get_appl_db, get_ipnetns_prefix, load_all_macsec_info, __check_appl_db
from tests.common.macsec.macsec_config_helper import (
    generate_macsec_profile,
    setup_macsec_multi_profile_configuration,
    disable_macsec_port,
    enable_macsec_port,
    delete_macsec_profile,
    replace_macsec_port
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]


class TestPerInterfaceProfile():
    '''
    Tests specific to per-interface MACsec profile functionality.
    Validates behaviours that only exist when different ports use
    different profiles simultaneously.
    Requires ``--per_interface_macsec`` to be set.
    '''

    def test_unique_keys(self, port_profiles, wait_mka_establish):
        '''Verify that each port was configured with a unique CAK/CKN pair
        '''
        if not port_profiles:
            pytest.skip("Requires --per_interface_macsec")
        profile_list = list(port_profiles.values())
        for i in range(len(profile_list)):
            for j in range(i + 1, len(profile_list)):
                assert profile_list[i]["primary_cak"] != profile_list[j]["primary_cak"], \
                    "CAK collision between {} and {}".format(
                        profile_list[i]["name"], profile_list[j]["name"])
                assert profile_list[i]["primary_ckn"] != profile_list[j]["primary_ckn"], \
                    "CKN collision between {} and {}".format(
                        profile_list[i]["name"], profile_list[j]["name"])

    @pytest.mark.disable_loganalyzer
    def test_profile_isolation(self, duthost, ctrl_links, upstream_links,
                               port_profiles, policy, cipher_suite, send_sci, tbinfo, wait_mka_establish):
        '''Disable MACsec on one port and verify other ports remain operational
        '''
        if not port_profiles:
            pytest.skip("Requires --per_interface_macsec")
        ports = list(ctrl_links.keys())
        target_port = ports[0]
        surviving_port = ports[1]
        target_nbr = ctrl_links[target_port]
        target_profile = port_profiles[target_port]

        disable_macsec_port(duthost, target_port)
        disable_macsec_port(target_nbr["host"], target_nbr["port"])

        try:
            def _surviving_ok():
                nbr = ctrl_links[surviving_port]
                pt, esc, isc, esa, isa = get_appl_db(
                    duthost, surviving_port, nbr["host"], nbr["port"])
                return bool(pt and esc and isc and pt.get("enable") == "true")
            assert wait_until(60, 3, 5, _surviving_ok), \
                "Surviving port {} lost MACsec after disabling {}".format(
                    surviving_port, target_port)

            if surviving_port in upstream_links:
                up = upstream_links[surviving_port]
                ret = duthost.command(
                    "{} ping -c 4 {}".format(
                        get_ipnetns_prefix(duthost, surviving_port),
                        up["local_ipv4_addr"]))
                assert not ret["failed"], \
                    "Ping failed on surviving port {}".format(surviving_port)
        finally:
            enable_macsec_port(duthost, target_port, target_profile["name"])
            enable_macsec_port(target_nbr["host"], target_nbr["port"],
                               target_profile["name"])
            assert wait_until(300, 3, 0,
                              lambda: duthost.iface_macsec_ok(target_port) and
                              target_nbr["host"].iface_macsec_ok(target_nbr["port"]) and
                              __check_appl_db(duthost, target_port, target_nbr, target_nbr["port"],
                                              policy, cipher_suite, send_sci)), \
                "MACsec did not recover on {}".format(target_port)

        load_all_macsec_info(duthost, ctrl_links, tbinfo)

    @pytest.mark.disable_loganalyzer
    def test_profile_replace(self, duthost, ctrl_links, port_profiles,
                             cipher_suite, policy, send_sci, default_priority,
                             rekey_period, tbinfo, wait_mka_establish):
        '''Replace the profile on one port and verify other ports are unaffected
        '''
        if not port_profiles:
            pytest.skip("Requires --per_interface_macsec")
        ports = list(ctrl_links.keys())
        target_port = ports[0]
        other_port = ports[1]
        target_nbr = ctrl_links[target_port]
        other_nbr = ctrl_links[other_port]

        _, _, _, orig_target_esa, _ = get_appl_db(
            duthost, target_port, target_nbr["host"], target_nbr["port"])

        new_profile = generate_macsec_profile(
            port_name=target_port,
            cipher_suite=cipher_suite,
            priority=default_priority,
            policy=policy,
            send_sci=send_sci,
            rekey_period=rekey_period,
        )
        new_profile["name"] = "MACSEC_PROFILE_{}_NEW".format(target_port)

        new_port_profiles = {target_port: new_profile}
        setup_macsec_multi_profile_configuration(
            duthost, {target_port: target_nbr}, new_port_profiles, tbinfo)

        try:
            def _check_new_sa():
                _, _, _, new_esa, _ = get_appl_db(
                    duthost, target_port, target_nbr["host"],
                    target_nbr["port"])
                if not new_esa:
                    return False
                return new_esa != orig_target_esa
            assert wait_until(60, 5, 2, _check_new_sa), \
                "SA keys did not change on {} after profile replace".format(
                    target_port)

            pt, _, _, other_esa, _ = get_appl_db(
                duthost, other_port, other_nbr["host"], other_nbr["port"])
            assert other_esa, "Other port {} lost SA tables".format(other_port)
            assert pt["cipher_suite"] == port_profiles[other_port]["cipher_suite"], \
                "Other port cipher changed unexpectedly"
        finally:
            # Replace profile on port back to the original, and clean up the test profile
            orig_port_profile = port_profiles[target_port]
            replace_macsec_port(duthost, target_port, orig_port_profile)
            replace_macsec_port(target_nbr["host"], target_nbr["port"], orig_port_profile)
            delete_macsec_profile(duthost, target_port, new_profile["name"])
            delete_macsec_profile(target_nbr["host"], target_nbr["port"], new_profile["name"])

            assert wait_until(300, 3, 0,
                              lambda: duthost.iface_macsec_ok(target_port) and
                              target_nbr["host"].iface_macsec_ok(target_nbr["port"]) and
                              __check_appl_db(duthost, target_port, target_nbr["host"], target_nbr["port"],
                                              policy, cipher_suite, send_sci)), \
                "MACsec did not recover on {}".format(target_port)

        load_all_macsec_info(duthost, ctrl_links, tbinfo)

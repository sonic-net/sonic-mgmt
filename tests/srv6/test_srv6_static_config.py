import time
import pytest

pytestmark = [
    pytest.mark.topology('t0', 't1')
]

WAIT_TIME = 5


def test_uN_config(duthosts, enum_frontend_dut_hostname, enum_rand_one_asic_index):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
    else:
        cli_options = ''

    sonic_db_cli = "sonic-db-cli" + cli_options
    vtysh_shell = "vtysh" + cli_options

    # add a locator configuration entry
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1::")
    # add a uN sid configuration entry
    duthost.command(sonic_db_cli +
                    " CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48 action uN decap_dscp_mode pipe")
    time.sleep(WAIT_TIME)

    frr_config = duthost.command(vtysh_shell + " -c \"show running-config\"")["stdout"]

    # verify that bgpcfgd generates FRR config correctly
    assert "locator loc1" in frr_config
    assert "sid fcbb:bbbb:1::/48 locator loc1 behavior uN" in frr_config

    appl_db_my_sids = duthost.command(sonic_db_cli + " APPL_DB keys SRV6_MY_SID_TABLE*")["stdout"]

    # verify that APPL_DB gets programmed by FRR correctly
    assert "SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1::" in appl_db_my_sids
    assert "un" == duthost.command(sonic_db_cli +
                                   " APPL_DB hget SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1:: action")["stdout"]

    # delete the configurations
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48")
    time.sleep(WAIT_TIME)

    frr_config = duthost.command(vtysh_shell + " -c \"show running-config\"")["stdout"]

    # verify that bgpcfgd deletes relevant FRR config
    assert "locator loc1" not in frr_config
    assert "sid fcbb:bbbb:1::/48 locator loc1 behavior uN" not in frr_config

    appl_db_my_sids = duthost.command(sonic_db_cli + " APPL_DB keys SRV6_MY_SID_TABLE*")["stdout"]

    # verify that the APPL_DB entry gets cleaned correctly
    assert "SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1::" not in appl_db_my_sids


def test_uDT46_config(duthosts, enum_frontend_dut_hostname, enum_rand_one_asic_index):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
    else:
        cli_options = ''

    sonic_db_cli = "sonic-db-cli" + cli_options
    vtysh_shell = "vtysh" + cli_options

    # add Vrf1 config
    duthost.command("config vrf add Vrf1")
    duthost.command("sysctl -w net.vrf.strict_mode=1")

    # add a locator configuration entry
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1::")
    # add a uDT46 sid configuration entry
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1:2::/64 \
                    action uDT46 decap_vrf Vrf1 decap_dscp_mode uniform")
    time.sleep(WAIT_TIME)

    frr_config = duthost.command(vtysh_shell + " -c \"show running-config\"")["stdout"]

    # verify that bgpcfgd generates FRR config correctly
    assert "locator loc1" in frr_config
    assert "sid fcbb:bbbb:1:2::/64 locator loc1 behavior uDT46 vrf Vrf1" in frr_config

    appl_db_my_sids = duthost.command(sonic_db_cli + " APPL_DB keys SRV6_MY_SID_TABLE*")["stdout"]

    # verify that APPL_DB gets programmed by FRR correctly
    assert "SRV6_MY_SID_TABLE:32:16:16:0:fcbb:bbbb:1:2::" in appl_db_my_sids
    assert "udt46" == duthost.command(sonic_db_cli +
                                      " APPL_DB hget SRV6_MY_SID_TABLE:32:16:16:0:fcbb:bbbb:1:2:: action")["stdout"]
    assert "Vrf1" == duthost.command(sonic_db_cli +
                                     " APPL_DB hget SRV6_MY_SID_TABLE:32:16:16:0:fcbb:bbbb:1:2:: vrf")["stdout"]

    # delete the configurations
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1:2::/64")
    time.sleep(WAIT_TIME)

    frr_config = duthost.command(vtysh_shell + " -c \"show running-config\"")["stdout"]

    # verify that bgpcfgd deletes relevant FRR config
    assert "locator loc1" not in frr_config
    assert "sid fcbb:bbbb:1:2::/64 locator loc1 behavior uDT46 vrf Vrf1" not in frr_config

    appl_db_my_sids = duthost.command(sonic_db_cli + " APPL_DB keys SRV6_MY_SID_TABLE*")["stdout"]

    # verify that the APPL_DB entry gets cleaned correctly
    assert "SRV6_MY_SID_TABLE:32:16:16:0:fcbb:bbbb:1:2::" not in appl_db_my_sids

    # delete the Vrf config
    duthost.command("config vrf del Vrf1")

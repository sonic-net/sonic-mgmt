import time
import logging
import pytest

WAIT_TIME = 5

def test_uN_config(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    # add a locator configuration entry
    duthost.command("sonic-db-cli CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1::")
    # add a uN sid configuration entry
    duthost.command("sonic-db-cli CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1:1:: action uN")
    time.sleep(WAIT_TIME)

    frr_config = duthost.command("vtysh -c \"show running-config\"")["stdout"]

    # verify that bgpcfgd generates FRR config correctly
    assert "locator loc1" in frr_config
    assert "sid fcbb:bbbb:1:1::/64 locator loc1 behavior uN" in frr_config

    appl_db_my_sids = duthost.command("sonic-db-cli APPL_DB keys SRV6_MY_SID_TABLE*")["stdout"]

    # verify that APPL_DB gets programmed by FRR correctly
    assert "SRV6_MY_SID_TABLE:32:16:16:0:fcbb:bbbb:1:1::" in appl_db_my_sids

    # delete the configurations
    duthost.command("sonic-db-cli CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    duthost.command("sonic-db-cli CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1:1::")
    time.sleep(WAIT_TIME)

    frr_config = duthost.command("vtysh -c \"show running-config\"")["stdout"]

    # verify that bgpcfgd deletes relevant FRR config
    assert "locator loc1" not in frr_config
    assert "sid fcbb:bbbb:1:1::/64 locator loc1 behavior uN" not in frr_config

    appl_db_my_sids = duthost.command("sonic-db-cli APPL_DB keys SRV6_MY_SID_TABLE*")["stdout"]

    # verify that the APPL_DB entry gets cleaned correctly
    assert "SRV6_MY_SID_TABLE:32:16:16:0:fcbb:bbbb:1:1::" not in appl_db_my_sids


def test_uDT46_config(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    # add Vrf1 config
    duthost.command("config vrf add Vrf1")
    duthost.command("sysctl -w net.vrf.strict_mode=1")

    # add a locator configuration entry
    duthost.command("sonic-db-cli CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1::")
    # add a uDT46 sid configuration entry
    duthost.command("sonic-db-cli CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1:2:: action uDT46 decap_vrf Vrf1")
    time.sleep(WAIT_TIME)

    frr_config = duthost.command("vtysh -c \"show running-config\"")["stdout"]

    # verify that bgpcfgd generates FRR config correctly
    assert "locator loc1" in frr_config
    assert "sid fcbb:bbbb:1:2::/64 locator loc1 behavior uDT46 vrf Vrf1" in frr_config

    appl_db_my_sids = duthost.command("sonic-db-cli APPL_DB keys SRV6_MY_SID_TABLE*")["stdout"]

    # verify that APPL_DB gets programmed by FRR correctly
    assert "SRV6_MY_SID_TABLE:32:16:16:0:fcbb:bbbb:1:2::" in appl_db_my_sids

    # delete the configurations
    duthost.command("sonic-db-cli CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    duthost.command("sonic-db-cli CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1:2::")
    time.sleep(WAIT_TIME)

    frr_config = duthost.command("vtysh -c \"show running-config\"")["stdout"]

    # verify that bgpcfgd deletes relevant FRR config
    assert "locator loc1" not in frr_config
    assert "sid fcbb:bbbb:1:2::/64 locator loc1 behavior uDT46 vrf Vrf1" not in frr_config

    appl_db_my_sids = duthost.command("sonic-db-cli APPL_DB keys SRV6_MY_SID_TABLE*")["stdout"]

    # verify that the APPL_DB entry gets cleaned correctly
    assert "SRV6_MY_SID_TABLE:32:16:16:0:fcbb:bbbb:1:2::" not in appl_db_my_sids

    # delete the Vrf config
    duthost.command("config vrf del Vrf1")
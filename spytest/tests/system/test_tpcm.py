import pytest
from spytest import st
from tests.system.tpcm import tpcm_dict, hdrMsg
import apis.system.basic as basic
import apis.system.interface as interf
import apis.system.reboot as reboot_api


@pytest.fixture(scope="module", autouse=True)
def tpcm_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1")
    hdrMsg("setup nameserver config")
    interface = st.get_mgmt_ifname(vars.D1)
    interf.enable_dhcp_on_interface(vars.D1, interface)
    hdrMsg("setup HTTPD docker which can be used as remote server for TPCM install and upgrade")
    basic.tpcm_operation(vars.D1, "install",tpcm_dict["httpd_docker"],"pull",image_path="httpd",tag_name="latest",
						 extra_args="--privileged -p 80:80 -v {} ".format(tpcm_dict["httpd_path"]))
    st.wait(5)
    if basic.verify_tpcm_list(vars.D1, docker_list=[tpcm_dict["httpd_docker"]],
                              image_list=[tpcm_dict["httpd_image"]],status_list=["Up"]):
        st.log("########## TPC {} installed successfully ##########".format(tpcm_dict["httpd_docker"]))
    else:
        st.error("########## FAIL: TPC {} not installed".format(tpcm_dict["httpd_docker"]))
        st.report_fail("base_config_verification_failed")

    hdrMsg("save existing {} image".format(tpcm_dict["httpd_docker"]))
    for image in [tpcm_dict["tpc1_image"],tpcm_dict["tpc2_image"],tpcm_dict["tpc3_image"],tpcm_dict["tpc4_image"]]:
        basic.save_docker_image(vars.D1,tpcm_dict["httpd_image"]," |gzip -c > "+tpcm_dict["tpc_path"]+image)
    yield
    hdrMsg("uninstall docker {}".format(tpcm_dict["httpd_docker"]))
    basic.tpcm_operation(vars.D1, "uninstall",tpcm_dict["httpd_docker"])
    basic.delete_directory_contents(vars.D1, tpcm_dict["tpc_path"])

@pytest.fixture(scope="function")
def tpcm_install_fixture(request,tpcm_hooks):
    for tpc,type,proto,path in zip([tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"]],["url"]*2,["HTTP","HTTPS"],
							 [tpcm_dict["tpc1_path"],tpcm_dict["tpc2_path"]]):
        hdrMsg("install docker {} using {} protocol".format(tpc,proto))
        basic.tpcm_operation(vars.D1,"install",tpc,type,image_path=path)

    for tpc,proto,path in zip([tpcm_dict["tpc3_name"],tpcm_dict["tpc4_name"]],["scp","sftp"],
                              [tpcm_dict["tpc_path"]+tpcm_dict["tpc3_image"],
                               tpcm_dict["tpc_path"]+tpcm_dict["tpc4_image"]]):
        hdrMsg("install docker {} using {} protocol".format(tpc,proto))
        if not basic.tpcm_operation(vars.D1,"install",tpc,proto,ser_name=tpcm_dict["ser_name"],
                                    user_name=tpcm_dict["uname"],pwd=tpcm_dict["pwd"],file_name=path,
                                    skip_error=True):
            hdrMsg("retry with alternate password")
            basic.tpcm_operation(vars.D1, "install", tpc, proto, ser_name=tpcm_dict["ser_name"],
                                    user_name=tpcm_dict["uname"],pwd=tpcm_dict["alt_pwd"],file_name=path)
    for tpc, type, path in zip([tpcm_dict["tpc5_name"], tpcm_dict["tpc6_name"]],
                               ["image", "file"], [tpcm_dict["httpd_image"],
                                                   tpcm_dict["tpc_path"] + tpcm_dict["tpc4_image"]]):
        hdrMsg("install docker {} using {} protocol".format(tpc, type))
        basic.tpcm_operation(vars.D1, "install", tpc, type, image_path=path)
    yield
    hdrMsg("uninstall {},{},{},{},{} and {}".format(tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"],
                                                    tpcm_dict["tpc3_name"],tpcm_dict["tpc4_name"],
                                                    tpcm_dict["tpc5_name"],tpcm_dict["tpc6_name"]))
    for tpc in [tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"],tpcm_dict["tpc3_name"],
                tpcm_dict["tpc4_name"],tpcm_dict["tpc5_name"],tpcm_dict["tpc6_name"]]:
        basic.tpcm_operation(vars.D1, "uninstall",tpc)


def test_FtOpSoStTpcm_11_3():
    success=True
    for tpc, type, proto, path in zip([tpcm_dict["tpc1_name"], tpcm_dict["tpc2_name"]],
                                       ["url"] * 2, ["HTTP", "HTTP"],
                                      [tpcm_dict["tpc1_path"], tpcm_dict["tpc2_path"]]):
        hdrMsg("install docker {} using {} protocol".format(tpc, proto))
        basic.tpcm_operation(vars.D1, "install", tpc, type, image_path=path)
    for tpc,proto,path in zip([tpcm_dict["tpc3_name"],tpcm_dict["tpc4_name"]],["scp","sftp"],
                              [tpcm_dict["tpc_path"]+tpcm_dict["tpc3_image"],
                               tpcm_dict["tpc_path"]+tpcm_dict["tpc4_image"]]):
        hdrMsg("install docker {} using {} protocol".format(tpc,proto))
        if not basic.tpcm_operation(vars.D1,"install",tpc,proto,ser_name=tpcm_dict["ser_name"],
                                    user_name=tpcm_dict["uname"],pwd=tpcm_dict["pwd"],file_name=path,
                                    skip_error=True):
            hdrMsg("retry with alternate password")
            basic.tpcm_operation(vars.D1, "install", tpc, proto, ser_name=tpcm_dict["ser_name"],
                                    user_name=tpcm_dict["uname"],pwd=tpcm_dict["alt_pwd"],file_name=path)
    hdrMsg("verify third party container details using \"tpcm list\"")
    if basic.verify_tpcm_list(vars.D1,image_list=[tpcm_dict["httpd_image"]]*4,
                              docker_list=[tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"],
                                          tpcm_dict["tpc3_name"],tpcm_dict["tpc4_name"]],
                              status_list=["Up"]*4):
        st.log("########## PASS: verification of tpcm list is passed ##########")
    else:
        st.error("########## FAIL: TPCM list verification failed")
        success = False
    hdrMsg("uninstall {},{},{} and {}".format(tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"],
                                              tpcm_dict["tpc3_name"],tpcm_dict["tpc4_name"]))
    for tpc in [tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"],tpcm_dict["tpc3_name"],tpcm_dict["tpc4_name"]]:
        basic.tpcm_operation(vars.D1, "uninstall",tpc)
    if not basic.verify_tpcm_list(vars.D1,image_list=[tpcm_dict["httpd_image"]]*4,
                                  docker_list=[tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"],
                                              tpcm_dict["tpc3_name"],tpcm_dict["tpc4_name"]],
                                  status_list=["Up"]*4):
        st.log("########## PASS: all TPCs uninstalled ##########")
    else:
        st.error("########## FAIL: all TPCs are not uninstalled ##########")
        success = False

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoStTpcm_11_3")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoStTpcm_11_3")


def test_FtOpSoStTpcm_14_2():
    success=True
    for tpc, type, path in zip([tpcm_dict["tpc1_name"], tpcm_dict["tpc2_name"]],
                                       ["image","file"], [tpcm_dict["httpd_image"],
                                                          tpcm_dict["tpc_path"]+tpcm_dict["tpc1_image"]]):
        hdrMsg("install docker {} using {} protocol".format(tpc, type))
        basic.tpcm_operation(vars.D1, "install", tpc, type, image_path=path)
    hdrMsg("verify third party container details using \"tpcm list\"")
    if basic.verify_tpcm_list(vars.D1,docker_list=[tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"]],
                              image_list=[tpcm_dict["httpd_image"]]*2,
                              status_list=["Up"]*2):
        st.log("########## PASS: verification of tpcm list is passed ##########")
    else:
        st.error("########## FAIL: TPCM list verification failed")
        success = False
    hdrMsg("uninstall {} and {}".format(tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"]))
    for tpc in [tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"]]:
        basic.tpcm_operation(vars.D1, "uninstall",tpc)
    if not basic.verify_tpcm_list(vars.D1,docker_list=[tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"]],
                                  image_list=[tpcm_dict["httpd_image"]]*2,
                                  status_list=["Up"]*2):
        st.log("########## PASS: all TPCs uninstalled ##########")
    else:
        st.error("########## FAIL: all TPCs are not uninstalled ##########")
        success = False

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoStTpcm_14_2")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoStTpcm_14_2")


@pytest.fixture(scope="function")
def tpcm_upgrade_fixture(request,tpcm_hooks):
    for tpc,type,proto,path in zip([tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"]],["url"]*2,["HTTP","HTTP"],
                             [tpcm_dict["tpc1_path"],tpcm_dict["tpc2_path"]]):
        hdrMsg("install docker {} using {} protocol".format(tpc,proto))
        basic.tpcm_operation(vars.D1,"install",tpc,type,image_path=path)

    for tpc,proto,path in zip([tpcm_dict["tpc3_name"],tpcm_dict["tpc4_name"]],["scp","sftp"],
                              [tpcm_dict["tpc_path"]+tpcm_dict["tpc3_image"],
                               tpcm_dict["tpc_path"]+tpcm_dict["tpc4_image"]]):
        hdrMsg("install docker {} using {} protocol".format(tpc,proto))
        if not basic.tpcm_operation(vars.D1,"install",tpc,proto,ser_name=tpcm_dict["ser_name"],
                                    user_name=tpcm_dict["uname"],pwd=tpcm_dict["pwd"],file_name=path,
                                    skip_error=True):
            hdrMsg("retry with alternate password")
            basic.tpcm_operation(vars.D1, "install", tpc, proto, ser_name=tpcm_dict["ser_name"],
                                    user_name=tpcm_dict["uname"],pwd=tpcm_dict["alt_pwd"],file_name=path)
    for tpc, type, path in zip([tpcm_dict["tpc5_name"], tpcm_dict["tpc6_name"]],
                               ["image", "file"], [tpcm_dict["httpd_image"],
                                                   tpcm_dict["tpc_path"] + tpcm_dict["tpc4_image"]]):
        hdrMsg("install docker {} using {} protocol".format(tpc, type))
        basic.tpcm_operation(vars.D1, "install", tpc, type, image_path=path)

    hdrMsg("create image {} from existing {}".format(tpcm_dict["upgrade_image"],tpcm_dict["httpd_docker"]))
    basic.commit_docker_image(vars.D1,tpcm_dict["httpd_docker"],tpcm_dict["upgrade_image"])
    basic.save_docker_image(vars.D1, tpcm_dict["upgrade_image"], " |gzip -c > " + tpcm_dict["tpc_path"] +
                            tpcm_dict["upgrade_file"])
    yield
    hdrMsg("uninstall {},{} and {}".format(tpcm_dict["tpc2_name"],tpcm_dict["tpc4_name"],
                                                    tpcm_dict["tpc6_name"]))
    for tpc in [tpcm_dict["tpc2_name"],tpcm_dict["tpc4_name"],tpcm_dict["tpc6_name"]]:
        basic.tpcm_operation(vars.D1, "uninstall",tpc)


def test_FtOpSoStTpcm_16(tpcm_upgrade_fixture):
    success=True

    for tpc, type, proto, path in zip([tpcm_dict["tpc1_name"], tpcm_dict["tpc2_name"]], ["url"] * 2, ["HTTP", "HTTP"],
                                      [tpcm_dict["upgrade_path"]]*2):
        hdrMsg("upgrade docker {} using {} protocol".format(tpc, proto))
        basic.tpcm_operation(vars.D1, "upgrade", tpc, type, image_path=path, skip_data="no")
    for tpc, proto, path in zip([tpcm_dict["tpc3_name"], tpcm_dict["tpc4_name"]], ["scp", "sftp"],
                                [tpcm_dict["tpc_path"] + tpcm_dict["upgrade_file"]]*2):
        hdrMsg("upgrade docker {} using {} protocol".format(tpc, proto))
        if not basic.tpcm_operation(vars.D1, "upgrade", tpc, proto, ser_name=tpcm_dict["ser_name"],
                                user_name=tpcm_dict["uname"], pwd=tpcm_dict["pwd"], file_name=path,skip_data="no",
                                skip_error=True):
            hdrMsg("retry with alternate password")
            basic.tpcm_operation(vars.D1, "upgrade", tpc, proto, ser_name=tpcm_dict["ser_name"],
                                 user_name=tpcm_dict["uname"], pwd=tpcm_dict["alt_pwd"], file_name=path,
                                 skip_data="no")
    for tpc, type, path in zip([tpcm_dict["tpc5_name"], tpcm_dict["tpc6_name"]],
                               ["image", "file"], [tpcm_dict["upgrade_image"],
                                                   tpcm_dict["tpc_path"] + tpcm_dict["upgrade_file"]]):
        hdrMsg("upgrade docker {} using {} protocol".format(tpc, type))
        basic.tpcm_operation(vars.D1, "upgrade", tpc, type, image_path=path,skip_data="no")
    if not basic.tpcm_operation(vars.D1, "upgrade", "NonExist", "image", image_path=tpcm_dict["upgrade_image"],
                            skip_data="yes",skip_error=True):
        st.log("########## PASS: upgrade failed for non existing TPC \"NonExist\" {} as expected")
    else:
        st.error("########## FAIL: upgrade happens for non existing TPC \"NonExist\" ##########")
        success=False
    hdrMsg("verify third party container details using \"tpcm list\"")
    if basic.verify_tpcm_list(vars.D1,docker_list=[tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"],
                                                   tpcm_dict["tpc3_name"],tpcm_dict["tpc4_name"],
                                                   tpcm_dict["tpc5_name"],tpcm_dict["tpc6_name"]],
                              image_list=[tpcm_dict["upgrade_image"]]*6,
                              status_list=["Up"]*6):
        st.log("########## PASS: verification of tpcm list is passed ##########")
    else:
        st.error("########## FAIL: TPCM list verification failed")
        success = False

    hdrMsg("uninstall {},{}, and {}".format(tpcm_dict["tpc1_name"],tpcm_dict["tpc3_name"],tpcm_dict["tpc5_name"]))
    for tpc in [tpcm_dict["tpc1_name"],tpcm_dict["tpc3_name"],tpcm_dict["tpc5_name"]]:
        basic.tpcm_operation(vars.D1, "uninstall",tpc)
    if basic.verify_tpcm_list(vars.D1,docker_list=[tpcm_dict["tpc2_name"],
                                                       tpcm_dict["tpc4_name"],
                                                       tpcm_dict["tpc6_name"]],
                                  image_list=[tpcm_dict["upgrade_image"]]*3,
                                  status_list=["Up"]*3):
        st.log("########## PASS: TPCs {},{} and {} remains intact ##########".format(tpcm_dict["tpc2_name"],
                tpcm_dict["tpc4_name"],tpcm_dict["tpc6_name"]))
    else:
        st.error("########## FAIL: TPCs {} or {} or {} not UP ##########".format(tpcm_dict["tpc2_name"],
                tpcm_dict["tpc4_name"],tpcm_dict["tpc6_name"]))
        success = False
    if not basic.verify_tpcm_list(vars.D1,docker_list=[tpcm_dict["tpc1_name"],
                                                       tpcm_dict["tpc3_name"],
                                                       tpcm_dict["tpc5_name"]],
                                  image_list=[tpcm_dict["upgrade_image"]]*3,
                                  status_list=["Up"]*3):
        st.log("########## PASS: TPCs {}, {}, and {} are uninstalled ##########".format(tpcm_dict["tpc1_name"],
                tpcm_dict["tpc3_name"],tpcm_dict["tpc5_name"],))
    else:
        st.error("########## FAIL: TPCs {} or {} or {} NOT uninstalled ##########".format(tpcm_dict["tpc1_name"],
                tpcm_dict["tpc3_name"],tpcm_dict["tpc5_name"],))
        success = False

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoStTpcm_16")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoStTpcm_16")


def test_FtOpSoStTpcm_17(tpcm_upgrade_fixture):
    success=True
    for tpc, type, proto, path in zip([tpcm_dict["tpc1_name"], tpcm_dict["tpc2_name"]], ["url"] * 2, ["HTTP", "HTTP"],
                                      [tpcm_dict["upgrade_path"]] * 2):
        hdrMsg("upgrade docker {} using {} protocol".format(tpc, proto))
        basic.tpcm_operation(vars.D1, "upgrade", tpc, type, image_path=path, skip_data="yes")
    for tpc, proto, path in zip([tpcm_dict["tpc3_name"], tpcm_dict["tpc4_name"]], ["scp", "sftp"],
                                [tpcm_dict["tpc_path"] + tpcm_dict["upgrade_file"]] * 2):
        hdrMsg("upgrade docker {} using {} protocol".format(tpc, proto))
        if not basic.tpcm_operation(vars.D1, "upgrade", tpc, proto, ser_name=tpcm_dict["ser_name"],
                                user_name=tpcm_dict["uname"], pwd=tpcm_dict["pwd"], file_name=path, skip_data="yes",
                                skip_error=True):
            hdrMsg("retry with alternate password")
            basic.tpcm_operation(vars.D1, "upgrade", tpc, proto, ser_name=tpcm_dict["ser_name"],
                                 user_name=tpcm_dict["uname"], pwd=tpcm_dict["alt_pwd"], file_name=path,
                                 skip_data="yes")
    for tpc, type, path in zip([tpcm_dict["tpc5_name"], tpcm_dict["tpc6_name"]],
                               ["image", "file"], [tpcm_dict["upgrade_image"],
                                                   tpcm_dict["tpc_path"] + tpcm_dict["upgrade_file"]]):
        hdrMsg("upgrade docker {} using {} protocol".format(tpc, type))
        basic.tpcm_operation(vars.D1, "upgrade", tpc, type, image_path=path, skip_data="yes")
    hdrMsg("verify third party container details using \"tpcm list\"")
    if basic.verify_tpcm_list(vars.D1,docker_list=[tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"],
                                                   tpcm_dict["tpc3_name"],tpcm_dict["tpc4_name"],
                                                   tpcm_dict["tpc5_name"],tpcm_dict["tpc6_name"]],
                              image_list=[tpcm_dict["upgrade_image"]]*6,
                              status_list=["Up"]*6):
        st.log("########## PASS: verification of tpcm list is passed ##########")
    else:
        st.error("########## FAIL: TPCM list verification failed")
        success = False
    hdrMsg("uninstall {},{}, and {}".format(tpcm_dict["tpc1_name"],tpcm_dict["tpc3_name"],tpcm_dict["tpc5_name"]))
    for tpc in [tpcm_dict["tpc1_name"],tpcm_dict["tpc3_name"],tpcm_dict["tpc5_name"]]:
        basic.tpcm_operation(vars.D1, "uninstall",tpc)
    if basic.verify_tpcm_list(vars.D1,docker_list=[tpcm_dict["tpc2_name"],
                                                       tpcm_dict["tpc4_name"],
                                                       tpcm_dict["tpc6_name"]],
                                  image_list=[tpcm_dict["upgrade_image"]]*3,
                                  status_list=["Up"]*3):
        st.log("########## PASS: TPCs {},{} and {} remains intact ##########".format(tpcm_dict["tpc2_name"],
                tpcm_dict["tpc4_name"],tpcm_dict["tpc6_name"]))
    else:
        st.error("########## FAIL: TPCs {} or {} or {} not UP ##########".format(tpcm_dict["tpc2_name"],
                tpcm_dict["tpc4_name"],tpcm_dict["tpc6_name"]))
        success = False
    if not basic.verify_tpcm_list(vars.D1,docker_list=[tpcm_dict["tpc1_name"],
                                                       tpcm_dict["tpc3_name"],
                                                       tpcm_dict["tpc5_name"]],
                                  image_list=[tpcm_dict["upgrade_image"]]*3,
                                  status_list=["Up"]*3):
        st.log("########## PASS: TPCs {}, {}, and {} are uninstalled ##########".format(tpcm_dict["tpc1_name"],
                tpcm_dict["tpc3_name"],tpcm_dict["tpc5_name"],))
    else:
        st.error("########## FAIL: TPCs {} or {} or {} NOT uninstalled ##########".format(tpcm_dict["tpc1_name"],
                tpcm_dict["tpc3_name"],tpcm_dict["tpc5_name"],))
        success = False

    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoStTpcm_17")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoStTpcm_17")


def test_FtOpSoStTpcm_21_3(tpcm_install_fixture):
    success=True
    hdrMsg("verify third party container details using \"tpcm list\"")
    if basic.verify_tpcm_list(vars.D1,docker_list=[tpcm_dict["tpc1_name"],tpcm_dict["tpc2_name"],
                                                   tpcm_dict["tpc3_name"],tpcm_dict["tpc4_name"],
                                                   tpcm_dict["tpc5_name"],tpcm_dict["tpc6_name"]],
                              image_list=[tpcm_dict["httpd_image"]]*6,
                              status_list=["Up"]*6):
        st.log("########## PASS: verification of tpcm list is passed ##########")
    else:
        st.error("########## FAIL: TPCM list verification failed")
        st.report_fail("test_case_id_failed", "test_FtOpSoStTpcm_21_3")
    hdrMsg("uninstall {} and {}".format(tpcm_dict["tpc1_name"],tpcm_dict["tpc3_name"]))
    for tpc in [tpcm_dict["tpc1_name"],tpcm_dict["tpc3_name"]]:
        basic.tpcm_operation(vars.D1, "uninstall",tpc)
    hdrMsg("stop TPC {} service".format(tpcm_dict["tpc5_name"]))
    basic.docker_operation(vars.D1, tpcm_dict["tpc5_name"], "stop")
    if not basic.verify_tpcm_list(vars.D1,docker_list=[tpcm_dict["tpc1_name"],tpcm_dict["tpc3_name"]],
                                  image_list=[tpcm_dict["httpd_image"]]*2,status_list=["Up"]*2):
        st.log("########## PASS: TPCs {} and {} are uninstalled ##########".format(tpcm_dict["tpc1_name"],
                                                                                   tpcm_dict["tpc3_name"]))
        st.report_tc_pass("test_FtOpSoStTpcm_21", "tc_passed")
    else:
        st.error("########## FAIL: TPCs {} or {} NOT uninstalled ##########".format(tpcm_dict["tpc1_name"],
                                                                                    tpcm_dict["tpc3_name"]))
        success = False
    if basic.verify_tpcm_list(vars.D1,docker_list=[tpcm_dict["tpc5_name"]],image_list=[tpcm_dict["httpd_image"]],
                              status_list=["Exited"]):
        st.log("########### PASS: TPC {} status is Exited as expected ##########".format(tpcm_dict["tpc5_name"]))
        st.report_tc_pass("test_FtOpSoStTpcm_22", "tc_passed")
    else:
        st.error("########## FAIL: TPC {} status is not \"Exited\"".format(tpcm_dict["tpc5_name"]))
        success = False
    for action in ["config"]:
        hdrMsg("trigger {} reboot in DUT1".format(action))
        if action == "warm":
            reboot_api.config_save(vars.D1)
            reboot_api.config_save(vars.D1, shell="vtysh")
            st.reboot(vars.D1, 'warm')
        else:
            reboot_api.config_reload(vars.D1)
        hdrMsg("verify third party container details after {} reboot".format(action))
        if basic.verify_tpcm_list(vars.D1,docker_list=[tpcm_dict["tpc2_name"],tpcm_dict["tpc4_name"],
                                                       tpcm_dict["tpc6_name"]],
                                  image_list=[tpcm_dict["httpd_image"]]*3,status_list=["Up"]*3):
            st.log("########## PASS: status of {},{} and {} are \"Up\" as expected after {} reboot"
                   " ##########".format(tpcm_dict["tpc2_name"],tpcm_dict["tpc4_name"],tpcm_dict["tpc6_name"],action))
        else:
            st.error("########## FAIL: status of {} or {} or {} NOT Up after {} reboot "
                     "#########".format(tpcm_dict["tpc2_name"],tpcm_dict["tpc4_name"],tpcm_dict["tpc6_name"],action))
            success = False
        if not basic.verify_tpcm_list(vars.D1,docker_list=[tpcm_dict["tpc1_name"],tpcm_dict["tpc3_name"]],
                                  image_list=[tpcm_dict["httpd_image"]]*2,status_list=["Up"]*2):
            st.log("########## PASS: {} and {} are not present as expected after {} reboot"
                   " #########".format(tpcm_dict["tpc1_name"],tpcm_dict["tpc3_name"],action))
        else:
            st.error("########## FAIL: {} and {} are present after {} reboot"
                     " #########".format(tpcm_dict["tpc1_name"],tpcm_dict["tpc3_name"],action))
            success = False
        if basic.verify_tpcm_list(vars.D1,docker_list=[tpcm_dict["tpc5_name"]],image_list=[tpcm_dict["httpd_image"]],
                                  status_list=["Exited"]):
            st.log("########## PASS: {} status is \"Exited\" as expected after {} reboot"
                   " #########".format(tpcm_dict["tpc5_name"], action))
        else:
            st.error("########## FAIL: status of {} is not \"Exited\" after {} reboot"
                     " #########".format(tpcm_dict["tpc5_name"], action))
            success = False

    hdrMsg("install back TPC1 using HTTP protocol")
    basic.tpcm_operation(vars.D1, "install", tpcm_dict["tpc1_name"], "url", image_path=tpcm_dict["tpc1_path"])
    hdrMsg("install back TPC3 using scp protocol")
    if not basic.tpcm_operation(vars.D1, "install", tpcm_dict["tpc3_name"], "scp", ser_name=tpcm_dict["ser_name"],
                            user_name=tpcm_dict["uname"], pwd=tpcm_dict["pwd"],
                            file_name=tpcm_dict["tpc_path"] + tpcm_dict["tpc3_image"],skip_error=True):
        hdrMsg("retry with alternate password")
        basic.tpcm_operation(vars.D1, "install", tpcm_dict["tpc3_name"], "scp", ser_name=tpcm_dict["ser_name"],
                             user_name=tpcm_dict["uname"], pwd=tpcm_dict["alt_pwd"],
                             file_name=tpcm_dict["tpc_path"] + tpcm_dict["tpc3_image"])
    hdrMsg("verify third party container details after completing all triggers")
    if basic.verify_tpcm_list(vars.D1, docker_list=[tpcm_dict["tpc1_name"], tpcm_dict["tpc2_name"],
                                                    tpcm_dict["tpc3_name"], tpcm_dict["tpc4_name"],
                                                    tpcm_dict["tpc6_name"]],
                              image_list=[tpcm_dict["httpd_image"]] * 5,
                              status_list=["Up"] * 5):
        st.log("########## PASS: verification of tpcm list is passed ##########")
    else:
        st.error("########## FAIL: TPCM list verification failed")
        success = False
    if success:
        st.report_pass("test_case_id_passed", "test_FtOpSoStTpcm_23")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoStTpcm_21_3")

import pytest
import os, subprocess, re

from spytest import st

import apis.system.ansible as ansible
import apis.system.basic as basic

@pytest.fixture(scope="module", autouse=True)
def ansible_st_module_hooks(request):
    global dut_dict, dut_ip_dict, host_name_dict, host_name_dict1
    dut_dict, dut_ip_dict, host_name_dict, host_name_dict1 = {}, {}, {}, {}

    st.ensure_min_topology("D1T1:2")
    dut_list = st.get_dut_names()
    for index in range(len(dut_list)):
        dut_name = "dut" + str(index)
        dut_dict[dut_name] = dut_list[index]
        dut = dut_list[index]
        st.log("get host name from DUTs")
        host_name = basic.get_hostname(dut)
        host_name_dict[dut_name] = host_name
        dut_ip_dict[dut_name] =  st.get_mgmt_ip(dut)
        new_host_name = "dut" + str(index) + str(index) + str(index)
        host_name_dict1[dut_name] = new_host_name
        st.log("create new host name in DUTs")
        basic.set_hostname(dut,host_name_dict1[dut_name])
    yield
    st.log("revert host name in DUTs")
    for key in dut_dict.keys():
        basic.set_hostname(dut_dict[key], host_name_dict[key])


@pytest.mark.ansible_st
def test_StSoMaVer011():

    success = True
    st.log('testcase to verify ansible with DCtopo playbook')
    for key in dut_dict.keys():
        if not ansible.verify_ansible_playbook_vdi(dut_dict[key],"backup.yml",
                host= dut_ip_dict[key], ok="2", changed="1", fail="0"):
            st.error("backup config_db json from DUT {} to Ansible server failed".format(dut_dict[key]))
            success = False
        else:
            st.log("backup config_db json from DUT {} to Ansible server passed".format(dut_dict[key]))

    for val in host_name_dict1.values():
        file_name = val + "_config_db.json"
        cfg_db_json = os.path.join(os.path.dirname(__file__), '../../', "ansible/files/", file_name)
        cfg_db_json = os.path.abspath(cfg_db_json)
        cmd = 'cat {} | grep fdb_aging_time'.format(cfg_db_json)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, _ = proc.communicate()
        if out.splitlines() != "":
            tmp = out.splitlines()
            tmp = tmp[0].strip()
            tmp = tmp.replace('"', '')
            tmp = tmp.split(":")
            aging_time = int(tmp[1])
            new_aging_time = aging_time / 10
            cmd = "sed -i 's/\"fdb_aging_time\": \"{}\"/\"fdb_aging_time\": \"{}\"/g' {}".\
                format(aging_time, new_aging_time, cfg_db_json)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            st.log("modified fdb_aging_time value from {} to {} in file {}".
                   format(aging_time, new_aging_time, file_name))
        else:
            st.error("attribute fdb_aging_time not found in server backup file {}".format(file_name))
            success = False

    for key in dut_dict.keys():
        if not ansible.verify_ansible_playbook_vdi(dut_dict[key],"apply.yml",
                host= dut_ip_dict[key], ok="2", changed="1", fail="0"):
            st.error("applying config_db json from Ansible server to DUT {} failed".format(dut_dict[key]))
            success = False
        else:
            st.log("applying config_db json from Ansible server to DUT {} passed".format(dut_dict[key]))

    st.log("verify config db file in DUTs")
    pattern = "\"fdb_aging_time\": \"{}\"".format(new_aging_time)
    for key in dut_dict.keys():
        out = basic.get_attr_from_cfgdbjson(dut_dict[key], "fdb_aging_time")
        if re.search(pattern,out):
            st.log("config db json file updated properly for DUT {}".format(dut_dict[key]))
        else:
            st.error("config db json file NOT updated properly for DUT {}".format(dut_dict[key]))
            success = False

    st.log("revert config db json file in DUTs")
    for key in dut_dict.keys():
        basic.update_config_db_json(dut_dict[key], "fdb_aging_time", new_aging_time, aging_time)
        pattern = "\"fdb_aging_time\": \"{}\"".format(aging_time)
        out = basic.get_attr_from_cfgdbjson(dut_dict[key], "fdb_aging_time")
        if re.search(pattern, out):
            st.log("config db json file reverted properly for DUT {}".format(dut_dict[key]))
        else:
            st.error("config db json file NOT reverted properly for DUT {}".format(dut_dict[key]))
            success = False

    st.log('remove the files created in ansible server')
    for val in host_name_dict1.values():
        file_name = val + "_config_db.json"
        file_name = os.path.join(os.path.dirname(__file__), '../../', "ansible/files/", file_name)
        file_name = os.path.abspath(file_name)
        os.unlink(file_name)

    if success:
        st.report_pass("test_case_id_passed","StSoMaVer011")
    else:
        st.report_fail("test_case_id_failed","StSoMaVer011")

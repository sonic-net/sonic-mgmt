import pytest
from spytest import st
from spytest.dicts import SpyTestDict
from apis.system.rest import rest_call, rest_status
import json
from spytest.utils import random_vlan_list

oc_yang_data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def oc_yang_ver_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1")
    credentials = st.get_credentials(vars.D1)
    oc_yang_data.username = credentials[0]
    oc_yang_data.password = credentials[3]
    oc_yang_data.dut_ip_addr = st.get_mgmt_ip(vars.D1)
    oc_yang_data.base_url = "restconf/data/"
    oc_yang_data.version = get_version(vars.D1)
    oc_yang_data.new_major_version = new_version(oc_yang_data.version)
    oc_yang_data.new_minor_version = new_version(oc_yang_data.version, flag="minor")
    oc_yang_data.new_patch_version = new_version(oc_yang_data.version, flag="patch")
    yield

@pytest.fixture(scope="function", autouse=True)
def oc_yang_ver_func_hooks(request):
    yield

def get_version(dut):
    rest_url = "{}ietf-yang-library:modules-state/module-set-id".format(oc_yang_data.base_url)
    headers = {"accept":"application/yang-data+json"}
    response = rest_call(dut, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='get', port="")
    st.log(response)
    if response:
        if not rest_status(response["status"]):
            st.log("Observed {} code in REST response".format(response["status"]))
            st.report_fail("rest_error_observed", response["status"])
        return json.loads(response["output"])["ietf-yang-library:module-set-id"]
    else:
        st.report_fail("no_response_found", rest_url)

def check_for_error(rest_url, response, negative=True):
    st.log("RESPONSE : {}".format(response))
    if response:
        if negative:
            if not rest_status(response["status"]):
                st.log("Observed {} code in REST response".format(response["status"]))
                st.report_fail("rest_error_observed", response["status"])
        else:
            if rest_status(response["status"]):
                st.log("Observed {} code in REST response".format(response["status"]))
                st.report_fail("rest_error_observed", response["status"])
        if response["status"] == 400:
            output = json.loads(response["output"])
            if output["ietf-restconf:errors"]["error"][0]["error-type"] != "protocol":
                st.report_fail("ocyang_error_is_not_as_per_the_design", "TYPE")
            elif output["ietf-restconf:errors"]["error"][0]["error-tag"] != "operation-not-supported":
                st.report_fail("ocyang_error_is_not_as_per_the_design", "TAG")
            elif "Unsupported client version" not in output["ietf-restconf:errors"]["error"][0]["error-message"]:
                st.report_fail("ocyang_error_is_not_as_per_the_design", "MESSAGE")
    else:
        st.report_fail("no_response_found", rest_url)

def new_version(version, flag="major"):
    if version:
        try:
            [major, minor, patch] = version.split(".")
            if flag == "major":
                major = str(int(major)+1)
            elif flag == "minor":
                minor = str(int(minor)+1)
            elif flag == "patch":
                patch = str(int(patch) + 1)
            return "{}.{}.{}".format(major, minor, patch)
        except ValueError as e:
            st.error(e)
            st.report_unsupported("ocyang_unsupported_build_version")
    return version


@pytest.mark.oc_yang_version
@pytest.mark.ocyang_patch
def test_ft_ocyang_patch():
    """
    Verify the bare bone oc yang version using correct, no version and incorrect version using PATCH call
    :return:
    """
    st.banner("Verifying with out version ...")
    rest_url = "{}openconfig-system:system/config/hostname".format(oc_yang_data.base_url)
    data = {"openconfig-system:hostname": "sonic"}
    headers = {"accept": "application/yang-data+json", "Content-Type": "application/yang-data+json"}
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='patch', data=data, port="")
    check_for_error(rest_url, response)
    st.banner("Verifying with wrong version as {}...".format(oc_yang_data.new_minor_version))
    headers.update({"accept-version":"{}".format(oc_yang_data.new_minor_version)})
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='patch', data=data, port="")
    check_for_error(rest_url, response, negative=False)
    st.banner("Verifying with actual version as {}...".format(oc_yang_data.version))
    headers.update({"accept-version": oc_yang_data.version})
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='patch', data=data, port="")
    check_for_error(rest_url, response)
    st.report_pass("bare_bone_ocyang_version_status", "PATCH", "SUCCESS")

@pytest.mark.oc_yang_version
@pytest.mark.ocyang_put
def test_ft_ocyang_put():
    """
    Verify the bare bone oc yang version using correct, no version and incorrect version using PUT call
    :return:
    """
    interface = st.get_free_ports(vars.D1)[0].replace("/", "%2F")
    mtu = 1500
    rest_url = "{}openconfig-interfaces:interfaces/interface={}/config/mtu".format(oc_yang_data.base_url, interface)
    headers = {"accept": "application/yang-data+json"}
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='get', port="")
    check_for_error(rest_url, response)
    config_mtu = int(json.loads(response["output"])["openconfig-interfaces:mtu"])
    st.banner("Verifying with out version ...")
    data = {"openconfig-interfaces:mtu": mtu}
    headers.update({"Content-Type": "application/yang-data+json"})
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='put', data=data, port="")
    check_for_error(rest_url, response)
    st.banner("Verifying with wrong version as {}...".format(oc_yang_data.new_major_version))
    headers.update({"accept-version":"{}".format(oc_yang_data.new_major_version)})
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='put', data=data, port="")
    check_for_error(rest_url, response, negative=False)
    st.banner("Verifying with actual version as {}...".format(oc_yang_data.version))
    headers.update({"accept-version": oc_yang_data.version})
    data = {"openconfig-interfaces:mtu": config_mtu}
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='put', data=data, port="")
    check_for_error(rest_url, response)
    st.report_pass("bare_bone_ocyang_version_status", "PUT", "SUCCESS")

@pytest.mark.oc_yang_version
@pytest.mark.ocyang_post
def test_ft_ocyang_post():
    """
    Verify the bare bone oc yang version using correct, no version and incorrect version using POST call
    :return:
    """
    rest_url = "{}openconfig-system:system/ssh-server".format(oc_yang_data.base_url)
    st.banner("Verifying with out version ...")
    data = json.dumps({
  "openconfig-system-ext:ssh-server-vrfs": {
    "ssh-server-vrf": [
      {
        "vrf-name": "Vrf100",
        "config": {
          "vrf-name": "Vrf100",
          "port": 22
        }
      }
    ]
  }
})
    headers = {"accept": "application/yang-data+json", "Content-Type": "application/yang-data+json"}
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='post', data=data, port="")
    check_for_error(rest_url, response)
    st.banner("Verifying with wrong version as {}...".format(oc_yang_data.new_minor_version))
    headers.update({"accept-version":"{}".format(oc_yang_data.new_minor_version)})
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='post', data=data, port="")
    check_for_error(rest_url, response, negative=False)
    headers.update({"accept-version": oc_yang_data.version})
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='delete', port="")
    check_for_error(rest_url, response)
    st.banner("Verifying with actual version as {}...".format(oc_yang_data.version))
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='post', data=data, port="")
    check_for_error(rest_url, response)
    st.report_pass("bare_bone_ocyang_version_status", "POST", "SUCCESS")

@pytest.mark.oc_yang_version
@pytest.mark.ocyang_get
def test_ft_ocyang_get():
    """
    Verify the bare bone oc yang version using correct, no version and incorrect version using GET call
    :return:
    """
    st.banner("Verifying with out version ...")
    rest_url = "{}openconfig-ztp:ztp".format(oc_yang_data.base_url)
    headers = {"accept": "application/yang-data+json"}
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='get', port="")
    check_for_error(rest_url, response)
    st.banner("Verifying with wrong version as {}...".format(oc_yang_data.new_major_version))
    headers.update({"accept-version":"{}".format(oc_yang_data.new_major_version)})
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='get', port="")
    check_for_error(rest_url, response, negative=False)
    st.banner("Verifying with actual version as {}...".format(oc_yang_data.version))
    headers.update({"accept-version": oc_yang_data.version})
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='get', port="")
    check_for_error(rest_url, response)
    st.report_pass("bare_bone_ocyang_version_status", "GET", "SUCCESS")

@pytest.mark.oc_yang_version
@pytest.mark.ocyang_delete
def test_ft_ocyang_delete():
    """
    Verify the bare bone oc yang version using correct, no version and incorrect version using DELETE call
    :return:
    """
    vlan_list = random_vlan_list(count=1)
    rest_url_patch = "{}openconfig-interfaces:interfaces/interface".format(oc_yang_data.base_url)
    data = {"openconfig-interfaces:interface": [{"name": "Vlan{}".format(vlan_list[0]),"config": {"name": "Vlan{}".format(vlan_list[0])}}]}
    headers = {"accept": "application/yang-data+json", "Content-Type": "application/yang-data+json"}
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url_patch, call_type='patch', data=data, port="")
    check_for_error(rest_url_patch, response)
    del headers["Content-Type"]
    rest_url = "{}openconfig-interfaces:interfaces/interface=Vlan{}".format(oc_yang_data.base_url, vlan_list[0])
    st.banner("Verifying with out version ...")
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='delete', port="")
    check_for_error(rest_url, response)
    st.banner("Verifying with wrong version as {}...".format(oc_yang_data.new_minor_version))
    headers.update({"accept-version":"{}".format(oc_yang_data.new_minor_version)})
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='delete', port="")
    check_for_error(rest_url, response, negative=False)
    headers = {"accept": "application/yang-data+json", "Content-Type": "application/yang-data+json"}
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url_patch, call_type='patch', data=data, port="")
    check_for_error(rest_url_patch, response)
    del headers["Content-Type"]
    st.banner("Verifying with actual version as {}...".format(oc_yang_data.version))
    headers.update({"accept-version": oc_yang_data.version})
    response = rest_call(vars.D1, headers=headers, username=oc_yang_data.username, password=oc_yang_data.password,
                         url=rest_url, call_type='delete', port="")
    check_for_error(rest_url, response)
    st.report_pass("bare_bone_ocyang_version_status", "DELETE", "SUCCESS")



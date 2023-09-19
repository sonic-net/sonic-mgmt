import inspect
from spytest import st


def get_method():
    method = st.getenv("SPYTEST_BASE_CONFIG_METHOD", "legacy")
    if method not in ["legacy", "klish", "config-db-click", "config-db-klish", "current"]:
        st.error("invalid base config method {}".format(method))
        method = "legacy"
    return method


python_script = '''
python -c 'import json
fp = open("/tmp/default_l2_config.json", "r")
data = json.load(fp)
fp.close()
del data["VLAN_MEMBER"]
del data["VLAN"]
for port_data in data["PORT"].values():
    port_data["admin_status"] = "down"
print(json.dumps(data, indent=2))' > /tmp/default_config.json
'''


def read_platform_summary(dut):
    output = st.show(dut, "show platform summary")
    if len(output) <= 0 or "hwsku" not in output[0]:
        return None
    return output[0]


def post_init_config(dut):
    pass


def init_config_db(dut):
    data = read_platform_summary(dut)
    if not data:
        st.report_fail("operation_failed")
        return
    dut_hwsku_value = data["hwsku"]

    st.config(dut, "sonic-cfggen --preset l2 -p -H -k {} > /tmp/default_l2_config.json".format(dut_hwsku_value))

    st.config(dut, python_script, sudo=False, split_cmds=False)
    st.config(dut, "cp /tmp/default_config.json /etc/sonic/config_db.json")
    st.config(dut, "cp /tmp/default_config.json /etc/sonic/default_config.json")
    st.config(dut, "cp /tmp/default_config.json /etc/sonic/golden_config.json")
    st.config(dut, "mkdir -p /etc/spytest")
    st.config(dut, "cp /tmp/default_config.json /etc/spytest/init_config_db.json")

    post_init_config(dut)


def init_config_db_click(dut):
    init_config_db(dut)
    st.reboot(dut, cli_type='click')


def init_config_db_klish(dut):
    init_config_db(dut)
    st.reboot(dut, cli_type='klish')


def init_config_db_current(dut):
    st.config(dut, "cp /etc/sonic/golden_config.json /etc/sonic/config_db.json")
    st.config(dut, "mkdir -p /etc/spytest")
    st.config(dut, "cp /etc/sonic/golden_config.json /etc/spytest/init_config_db.json")


def init_klish(dut):
    cli_type = st.get_ui_type(dut)
    if cli_type == 'click':
        st.config(dut, "config erase -y")
    else:
        st.config(dut, 'do write erase', type='klish', confirm='y')
    post_init_config(dut)
    st.reboot(dut, cli_type='klish')


def init(dut, type):
    if type != "base":
        return

    method = get_method()
    st.log("init base config using {} method".format(method), dut=dut)
    from apis.system import basic
    basic.clear_core_files(dut)
    if method == "klish":
        init_klish(dut)
    elif method == "config-db-click":
        init_config_db_click(dut)
    elif method == "config-db-klish":
        init_config_db_klish(dut)
    elif method == "current":
        init_config_db_current(dut)
    else:
        st.init_base_config_db(dut)


def remove_vlan_1(dut, phase):
    if not st.is_feature_supported("sai-removes-vlan-1", dut):
        st.banner("Remove VLAN-1 {}".format(phase), dut=dut)
        import apis.common.asic as asicapi
        asicapi.remove_vlan_1(dut)
        asicapi.dump_vlan(dut)


def post_reboot(dut, is_upgrade=False):
    remove_vlan_1(dut, "post reboot")


def post_config_reload(dut):
    remove_vlan_1(dut, "post config reload")
    post_init_config(dut)


def init_default_config(dut):
    from apis.qos import qos as qos_api
    from apis.routing import bgp as bgp_api
    from apis.system import lldp as lldp_api
    from apis.system import sflow as sflow_api
    from apis.routing import nat as nat_api
    qos_api.init_default_config(dut)
    bgp_api.init_default_config(dut)
    lldp_api.init_default_config(dut)
    sflow_api.init_default_config(dut)
    nat_api.init_default_config(dut)

    remove_vlan_1(dut, "base config")


def extend(dut, type):
    if type != "base":
        return

    st.log("Extend base config if needed", dut=dut)

    init_default_config(dut)

    # GNMI connection init
    if st.getenv("SPYTEST_GNMI_INIT", "1") != "0":
        try:
            from apis.yang.utils.gnmi import get_gnmi_conn
            get_gnmi_conn(dut, False, False, False)
        except Exception:
            pass


def verify(dut, type):
    st.log("verify {} config if needed".format(type), dut=dut)
    return True

# phase 0: session init 1: module init 2: session clean


def apply(dut, phase):
    if phase == 2:
        return True
    if phase == 0 and get_method() != "legacy":
        return True
    init_default_config(dut)
    return st.apply_base_config_db(dut)


def clear(dut, **kwargs):
    return None


def save(dut, type="base"):
    if get_method() == "legacy" or type != "base":
        st.save_config_db(dut, type)
    else:
        st.config(dut, "config save -y")
        st.config(dut, "mkdir -p /etc/spytest")
        st.config(dut, "cp -f /etc/sonic/config_db.json /etc/spytest/init_config_db.json")
        st.config(dut, "rm -f /etc/spytest/base_*.*")
        st.config(dut, "cp /etc/spytest/init_config_db.json /etc/spytest/base_config_db.json")
        st.config(dut, "cp /etc/spytest/init_config_db.json /etc/sonic/golden_config.json")


def show_sai_profile(dut, platform=None, hwsku=None):
    if platform is None or hwsku is None:
        data = read_platform_summary(dut)
        if not data:
            st.error("failed to enable sai-profile")
            return

    # build file path
    platform = platform or data["platform"]
    hwsku = hwsku or data["hwsku"]
    file_path = "/usr/share/sonic/device/{}/{}/sai.profile".format(platform, hwsku)

    # dump current value
    st.show(dut, "cat {}".format(file_path), skip_tmpl=True)

    # enable
    # st.config(dut, 'bash -c "echo true > {}" '.format(file_path))


def gnmi_cert_config_ensure(dut):
    if st.getenv("SPYTEST_GNMI_INIT", "1") != "0":
        try:
            from apis.yang.utils.gnmi import ensure_gnmi_config_and_cert
            ensure_gnmi_config_and_cert(dut)
        except Exception:
            pass


def get_custom_ui(dut):
    file_name_list = ['apis/routing/bgp.py', 'apis/routing/ip_bgp.py', 'apis/routing/ospf.py',
                      'apis/routing/bfd.py', 'apis/routing/pim.py', 'apis/routing/ip.py']
    exception_fname_list = ['apis/routing/ip.py']
    exception_api_list = ['create_static_route', 'delete_static_route', 'create_static_route_nexthop_vrf']
    calling_api_filename, calling_api_name = '', ''
    for each_frame in inspect.stack():
        frame_info = inspect.getframeinfo(each_frame[0])
        calling_api_filename = getattr(frame_info, 'filename')
        calling_api_name = getattr(frame_info, 'function')
        for file_name in file_name_list:
            if file_name in calling_api_filename and calling_api_name not in exception_api_list:
                if not [fname for fname in exception_fname_list if fname in calling_api_filename]:
                    cli_type = "click"
                    st.debug("get_custom_ui ({}): cli_type: {}".format(calling_api_name, cli_type))
                    return cli_type
    cli_type = "klish"
    st.debug("get_custom_ui: cli_type: {}".format(cli_type))
    return cli_type

import pytest
import re
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from spytest import st
from spytest.dicts import SpyTestDict
from tests.cisco.hwqual.platform_edvt_cfg import platform_edvt_cfg
from apis.common.sonic_hooks import SonicHooks

@pytest.fixture(scope="module", autouse=True)
def systemctl_check_hooks(request):
    global TBDataG
    global CfgDataG

    TBDataG = st.get_testbed_vars()
    CfgDataG = SpyTestDict()

    CfgDataG.logprefix = "*** SYSTEMCTL CHECK *** :"
    CfgDataG.username = st.get_username(TBDataG.D1)
    CfgDataG.password = st.get_password(TBDataG.D1)
    CfgDataG.homedir = "/home/" + CfgDataG.username + "/"
    CfgDataG.dut = TBDataG.D1

    yield
    pass


def report_fail(msg=''):
    st.error(msg)
    st.report_fail('test_case_failed', msg)

def check_systemd_service_status(dut, service, result):
    '''
    return 0 if service is inactive or service is active(exited) and status != 0/SUCCESS
    return 1 if service is active(running) or service is active(exited) and status == 0/SUCCESS
    '''
    cmd1 = "systemctl is-active {}".format(service)
    output = st.config(dut, cmd1)
    status = output.split("\n")[0]
    if status != 'active':
        d = {}
        d[service] = 'Failed'
        d['reason'] = 'Not Active'
        result.append(d)
        return False
    else:
        cmd2 = "systemctl status {}".format(service)
        output = st.config(dut, cmd2)
        active_status = re.search(r"(Active:.*)\)",output)
        active_status = active_status.group(0)
        if('running' in active_status):
            return True
        elif('exited' in active_status):
            if('status=0/SUCCESS' in output):
                return True
    return False

def test_systemctl_check(CfgDataG, services_check, result):
    st.log(f"{CfgDataG.logprefix}: Executing {services_check} check")

    for check_item in services_check:
        if not check_systemd_service_status(CfgDataG.dut, check_item, result):
            report_fail(f"{CfgDataG.logprefix}: systemtl service {check_item} failed")
            return False
        st.log(f"{CfgDataG.logprefix}: {check_item} status ok")

    return True

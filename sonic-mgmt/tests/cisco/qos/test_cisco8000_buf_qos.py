import pytest
import logging
from tests.cisco.common.utils import skip_if_not_sim

pytestmark = [ pytest.mark.topology('t1') ]

#
# list of pid and sku that cisco-8000 supports
# update when new pid/sku is enabled for RDMA
#
pid_sku = [{"x86_64-8102_64h_o-r0" : ["Cisco-8102-C64"]},
           {"x86_64-8101_32h_o-r0" : ["32x100Gb"]},
           {"x86_64-8111_32eh_o-r0": ["Cisco-8111-O32", "Cisco-8111-O64", "Cisco-8111-O62C2"]},
           {"x86_64-88_lc0_36fh_mo-r0" : [("Cisco-88-LC0-36FH-M-O36", [0,1,2])]},
           {"x86_64-88_lc0_36fh_m-r0" : [("Cisco-88-LC0-36FH-M-O36", [0,1,2])]},
           {"x86_64-88_lc0_36fh_o-r0" : [("Cisco-88-LC0-36FH-O36", [0,1,2])]},
           {"x86_64-88_lc0_36fh-r0" : [("Cisco-88-LC0-36FH-O36", [0,1,2])]},
           {"x86_64-8101_32fh_o-r0" : ["32x400Gb", "Cisco-8101-C64", "Cisco-8101-O32", "Cisco-8101-O8C48", "Cisco-DSF-8101-32FH"]},
           {"x86_64-8800_rp_o-r0" : [""]}
           ]

def print_rc(cmd, rc):
    if rc.is_successful:
        logging.info("Success :{}".format(cmd))
    else:
        logging.error("Failed :{}".format(cmd))


def get_pid_sku(pid_sku):
    for pid in pid_sku:
        for sku in pid_sku[pid]:
            if isinstance(sku, tuple):
                t2_sku, t2_asics = sku
                for asic in t2_asics:
                    path = "{}/{}/{}".format(pid, t2_sku, str(asic))
                    logging.info("path {} sku {} asic {}".format(path, t2_sku, str(asic)))
                    yield path, pid, t2_sku
            else:
                path = "{}/{}".format(pid, sku)
                logging.info("path {} sku {}".format(path, sku))
                yield path, pid, sku


def run_mmu_config(duthost, raw_pid_sku, mmucommand):
    prefix = '/usr/share/sonic/device'
    output_file = '/tmp/_cfggen_'
    for pidpath, pid, sku in get_pid_sku(raw_pid_sku):
        if pid == "x86_64-8111_32eh_o-r0":
            additional_data = '{"DEVICE_METADATA": {"localhost": {"platform": "%s", "type": "BackEndLeafRouter", "resource_type": "ComputeAI"}}}' % pid
        else:
            additional_data = '{"DEVICE_METADATA": {"localhost": {"platform": "%s"}}}' % pid
        cfggen = 'sonic-cfggen -t {}/{}/{} -k {} -a \'{}\' > {}'.format(prefix, pidpath, mmucommand, sku if sku else '""', additional_data, output_file)
        logging.info("executing {} for pid/sku {}".format(cfggen, pidpath))
        try:
            rc = duthost.shell(cfggen)
            print_rc(cfggen, rc)
        except:
            pytest.fail("{} failed for pid/sku {}".format(mmucommand, pidpath))
        json_cmd = 'jq < {}'.format(output_file)
        logging.info("executing {} for pid/sku {}".format(json_cmd, pidpath))
        try:
            rc = duthost.shell(json_cmd)
            print_rc(json_cmd, rc)
        except:
            pytest.fail("{} for {} failed for pid/sku {}".format(json_cmd, mmucommand, pidpath))
        duthost.shell("rm {}".format(output_file))


@pytest.mark.parametrize("raw_pid_sku", pid_sku)
@pytest.mark.parametrize("mmucommand", ["buffers.json.j2", "qos.json.j2"])
def test_mmu_config(duthosts, raw_pid_sku, mmucommand, enum_rand_one_per_hwsku_hostname, skip_if_not_sim):
    for duthost in duthosts:
        if duthost.facts["asic_type"] != "cisco-8000":
            pytest.skip("Test is only supported for cisco-8000")
        run_mmu_config(duthost, raw_pid_sku, mmucommand)

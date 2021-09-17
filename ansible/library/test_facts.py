#!/usr/bin/env python
import os
import sys
import traceback
import ipaddr as ipaddress
import csv
import string
import yaml

from collections import defaultdict

DOCUMENTATION = '''
module: test_facts.py
version_added:  2.0.0.2
short_description: get lab testbed and testcases information related to run tests
options:
    - testbed_file:
      Description: the CSV file name which describe all testbeds
      Default: TESTBED_FILE
      required: False
    - testbed_name:
      Description: the unique name of one testbed topology specified in the first column of each row of CSV file
      Default: None
      Required: False
    - testcases_file:
      Description: the yml file name which include all testcases properties
      Dedfault: TESTCASES_FILE
      required: False
'''

EXAMPLES = '''
    Testbed CSV file example - deprecated:
        # conf-name,group-name,topo,ptf_image_name,ptf,ptf_ip,ptf_ipv6,server,vm_base,dut,comment
        ptf1-m,ptf1,ptf32,docker-ptf,ptf-1,10.255.0.188/24,,server_1,,str-msn2700-01,Tests ptf
        vms-t1,vms1-1,t1,docker-ptf,ptf-2,10.255.0.178/24,,server_1,VM0100,str-msn2700-01,Tests vms
        vms-t1-lag,vms1-1,t1-lag,docker-ptf,ptf-3,10.255.0.178/24,,server_1,VM0100,str-msn2700-01,Tests vms
        ...

    Testbed CSV file example - recommended:
        # conf-name,group-name,topo,ptf_image_name,ptf,ptf_ip,ptf_ipv6,server,vm_base,dut,inv_file,auto_recover,comment
        ptf1-m,ptf1,ptf32,docker-ptf,ptf-1,10.255.0.188/24,,server_1,,str-msn2700-01,lab,False,Tests ptf
        vms-t1,vms1-1,t1,docker-ptf,ptf-2,10.255.0.178/24,,server_1,VM0100,str-msn2700-01,lab,True,Tests vms
        vms-t1-lag,vms1-1,t1-lag,docker-ptf,ptf-3,10.255.0.178/24,,server_1,VM0100,str-msn2700-01,lab,True,Tests vms
        ...

    Testcases YAML File example:
        testcases:
            acl:
                filename: acl.yml
                topologies: [t1, t1-lag, t1-64-lag, t1-64-lag-clet]
                execvar:
                  ptf_host:
                  testbed_type:
            arp:
                filename: arpall.yml
                topologies: [ptf32, ptf64]
                execvars:
                  ptf_host:
            bgp_fact:
                filename: bgp_fact.yml
                topologies: [t0, t0-64, t0-64-32, t1, t1-lag, t1-64-lag, t1-64-lag-clet]
            ...

    To use it:
    - name: gather all predefined testbed topology information
      test_facts:

    - name: get vms-t1 topology information
      test_facts: testbed_name="vms-t1"
'''

RETURN = '''
    Ansible_facts:
        "testbed_facts": {
            "vms1-1": {
                "dut": "str-s6000-1",
                "owner": "Tests vms",
                "ptf_image_name": "docker-ptf",
                "ptf_ip": "10.255.0.178",
                "ptf_netmask": "255.255.255.0",
                "server": "server_1",
                "testbed-name": "vmst-1",
                "topo": "t1",
                "vm_base": "VM0100"
            }
            ....
        }
        "topo_testcases": {
                ptf32:     [arpall, copp, everflow, neighbour, neighbour_mac_noptf, qos, snmp, syslog]
                ptf64:     [arpall, copp, everflow, neighbour, neighbour_mac_noptf, qos, snmp, syslop]
                t0:        [bgp_fact, bgp_speaker, decap, dhcp_relay, fast-reboot, fib, fdb, lldp, lag_2, pfc_wd]
                t0-64:     [bgp_fact, bgp_speaker, decap, dhcp_relay, fast-reboot, fib, fdb, lldp, lag_2, pfc_wd]
                t0-64-32:  [bgp_fact, bgp_speaker, decap, dhcp_relay, fast-reboot, fib, fdb, lldp, lag_2, pfc_wd]
                t1:        [acl, bgp_fact, bgp_multipath_relax, decap, everflow_testbed, fib, lldp, pfc_wd]
                t1-lag:    [acl, bgp_fact, bgp_multipath_relax, decap, everflow_testbed, fib, lldp, lag_2, pfc_wd]
                t1-64-lag: [acl, bgp_fact, bgp_multipath_relax, decap, everflow_testbed, fib, lldp, lag_2, pfc_wd]
                t1-64-lag-clet: [acl, bgp_fact, bgp_multipath_relax, decap, everflow_testbed, fib, lldp, lag_2, pfc_wd]
            }
'''

### Default testbed file name
TESTBED_FILE = 'testbed.csv'
TESTCASE_FILE = 'roles/test/vars/testcases.yml'


class ParseTestbedTopoinfo():
    """Parse the testbed file used to describe whole testbed info"""

    TESTBED_FIELDS_DEPRECATED = ('conf-name', 'group-name', 'topo', 'ptf_image_name', 'ptf', 'ptf_ip', 'ptf_ipv6', 'server', 'vm_base', 'dut', 'comment')
    TESTBED_FIELDS_RECOMMENDED = ('conf-name', 'group-name', 'topo', 'ptf_image_name', 'ptf', 'ptf_ip', 'ptf_ipv6', 'server', 'vm_base', 'dut', 'inv_name', 'auto_recover', 'comment')

    def __init__(self, testbed_file):
        self.testbed_filename = testbed_file
        self.testbed_topo = defaultdict()

    def read_testbed_topo(self):

        def _cidr_to_ip_mask(network):
            addr = ipaddress.IPNetwork(network)
            return str(addr.ip), str(addr.netmask)

        def _read_testbed_topo_from_csv():
            """Read csv testbed info file."""
            with open(self.testbed_filename) as f:
                header = [field.strip(' #') for field in f.readline().strip().split(',')]
                if len(header) == len(self.TESTBED_FIELDS_DEPRECATED):
                    testbed_fields = self.TESTBED_FIELDS_DEPRECATED
                elif len(header) == len(self.TESTBED_FIELDS_RECOMMENDED):
                    testbed_fields = self.TESTBED_FIELDS_RECOMMENDED
                else:
                    raise ValueError('Unsupported testbed fields %s' % str(header))
                for header_field, expect_field in zip(header, testbed_fields):
                    assert header_field == expect_field

                topo = csv.DictReader(f, fieldnames=testbed_fields, delimiter=',')

                for line in topo:
                    if line['conf-name'].lstrip().startswith('#'):
                        # skip comment line
                        continue
                    if line['ptf_ip']:
                        line['ptf_ip'], line['ptf_netmask'] = \
                            _cidr_to_ip_mask(line["ptf_ip"])
                    if line['ptf_ipv6']:
                        line['ptf_ipv6'], line['ptf_netmask_v6'] = \
                            _cidr_to_ip_mask(line["ptf_ipv6"])

                    if sys.version_info < (3, 0):
                        line['duts'] = line['dut'].translate(string.maketrans("", ""), "[] ").split(';')
                    else:
                        line['duts'] = line['dut'].translate(str.maketrans("", "", "[] ")).split(';')
                    line['duts_map'] = {dut: line['duts'].index(dut) for dut in line['duts']}
                    del line['dut']

                    self.testbed_topo[line['conf-name']] = line

        def _read_testbed_topo_from_yaml():
            """Read yaml testbed info file."""
            with open(self.testbed_filename) as f:
                tb_info = yaml.safe_load(f)
                for tb in tb_info:
                    if tb["ptf_ip"]:
                        tb["ptf_ip"], tb["ptf_netmask"] = \
                            _cidr_to_ip_mask(tb["ptf_ip"])
                    if tb["ptf_ipv6"]:
                        tb["ptf_ipv6"], tb["ptf_netmask_v6"] = \
                            _cidr_to_ip_mask(tb["ptf_ipv6"])
                    tb["duts"] = tb.pop("dut")
                    tb["duts_map"] =  \
                        {dut: i for i, dut in enumerate(tb["duts"])}
                    self.testbed_topo[tb["conf-name"]] = tb

        if self.testbed_filename.endswith(".csv"):
            _read_testbed_topo_from_csv()
        elif self.testbed_filename.endswith(".yaml"):
            _read_testbed_topo_from_yaml()

    def get_testbed_info(self, testbed_name):
        if testbed_name:
            return self.testbed_topo[testbed_name]
        else:
            return self.testbed_topo


class TestcasesTopology():
    '''
    Read testcases definition yaml file under ansible/roles/test/vars/testcases.yml
    and return a list of available testcases for each pre-defined testbed topology
    '''
    def __init__(self, testcase_file):
        self.testcase_filename = testcase_file
        self.topo_testcase = {}

    def read_testcases(self):
        with open(self.testcase_filename) as f:
            testcases = yaml.load(f)
            if 'testcases' not in testcases:
                raise Exception("not correct testcases file format??")
            for tc,prop in testcases['testcases'].items():
                for topo in prop['topologies']:
                    if topo not in self.topo_testcase:
                        self.topo_testcase[topo] = []
                    self.topo_testcase[topo].append(tc)
            return testcases['testcases']

    def get_topo_testcase(self):
        return self.topo_testcase


def main():
    module = AnsibleModule(
        argument_spec=dict(
            testbed_name=dict(required=False, default=None),
            testbed_file=dict(required=False, default=TESTBED_FILE),
            testcase_file=dict(requried=False, default=TESTCASE_FILE),
        ),
        supports_check_mode=True
    )
    m_args = module.params
    testbed_file = m_args['testbed_file']
    testbed_name = m_args['testbed_name']
    testcase_file = m_args['testcase_file']
    try:
        topoinfo = ParseTestbedTopoinfo(testbed_file)
        topoinfo.read_testbed_topo()
        testbed_topo = topoinfo.get_testbed_info(testbed_name)
        testcaseinfo = TestcasesTopology(testcase_file)
        testcaseinfo.read_testcases()
        testcase_topo = testcaseinfo.get_topo_testcase()
        module.exit_json(ansible_facts={'testbed_facts': testbed_topo, 'topo_testcases': testcase_topo})
    except (IOError, OSError):
        module.fail_json(msg="Can not find lab testbed file  "+testbed_file+" or testcase file "+testcase_file+"??")
    except Exception as e:
        module.fail_json(msg=traceback.format_exc())


from ansible.module_utils.basic import *
if __name__== "__main__":
    main()

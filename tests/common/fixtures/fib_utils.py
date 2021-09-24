import json
import logging
import tempfile

from datetime import datetime

import pytest

logger = logging.getLogger(__name__)


def get_t2_fib_info(duthosts, duts_cfg_facts, duts_mg_facts):
    """Get parsed FIB information from redis DB for T2 topology.

    Args:
        duthosts (DutHosts): Instance of DutHosts for interacting with DUT hosts
        duts_cfg_facts (dict): Running config facts of all DUT hosts.
        duts_mg_facts (dict): Minigraph facts of all DUT hosts.

    Returns:
        dict: Map of prefix to PTF ports that are connected to DUT output ports.
            {
                '192.168.0.0/21': [],
                '192.168.8.0/25': [[58 59] [62 63] [66 67] [70 71]],
                '192.168.16.0/25': [[58 59] [62 63] [66 67] [70 71]],
                ...
                '20c0:c2e8:0:80::/64': [[58 59] [62 63] [66 67] [70 71]],
                '20c1:998::/64': [[58 59] [62 63] [66 67] [70 71]],
                ...
            }
    """
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    fib_info = {}
    for duthost in duthosts.frontend_nodes:
        cfg_facts = duts_cfg_facts[duthost.hostname]
        mg_facts = duts_mg_facts[duthost.hostname]
        for asic_index, asic_cfg_facts in  enumerate(cfg_facts):
            asic = duthost.asic_instance(asic_index)

            asic.shell("{} redis-dump -d 0 -k 'ROUTE*' -y > /tmp/fib.{}.txt".format(asic.ns_arg, timestamp))
            duthost.fetch(src="/tmp/fib.{}.txt".format(timestamp), dest="/tmp/fib")

            po = asic_cfg_facts.get('PORTCHANNEL', {})
            ports = asic_cfg_facts.get('PORT', {})

            with open("/tmp/fib/{}/tmp/fib.{}.txt".format(duthost.hostname, timestamp)) as fp:
                fib = json.load(fp)
                for k, v in fib.items():
                    skip = False

                    prefix = k.split(':', 1)[1]
                    ifnames = v['value']['ifname'].split(',')
                    nh = v['value']['nexthop']

                    oports = []
                    for ifname in ifnames:
                        if po.has_key(ifname):
                            # ignore the prefix, if the prefix nexthop is not a frontend port
                            if 'members' in po[ifname]:
                                if 'role' in ports[po[ifname]['members'][0]] and ports[po[ifname]['members'][0]]['role'] == 'Int':
                                    if len(oports) == 0:
                                        skip = True
                                else:
                                    oports.append([str(mg_facts['minigraph_ptf_indices'][x]) for x in po[ifname]['members']])
                                    skip = False
                        else:
                            if ports.has_key(ifname):
                                if 'role' in ports[ifname] and ports[ifname]['role'] == 'Int':
                                    if len(oports) == 0:
                                        skip = True
                                else:
                                    oports.append([str(mg_facts['minigraph_ptf_indices'][ifname])])
                                    skip = False
                            else:
                                logger.info("Route point to non front panel port {}:{}".format(k, v))
                                skip = True

                    # skip direct attached subnet
                    if nh == '0.0.0.0' or nh == '::' or nh == "":
                        skip = True

                    if not skip:
                        if prefix in fib_info:
                            fib_info[prefix] += oports
                        else:
                            fib_info[prefix] = oports

    return fib_info


def get_fib_info(duthost, dut_cfg_facts, duts_mg_facts):
    """Get parsed FIB information from redis DB.

    Args:
        duthost (SonicHost): Object for interacting with DUT.
        duts_cfg_facts (dict): Running config facts of all DUT hosts.
        duts_mg_facts (dict): Minigraph facts of all DUT hosts.

    Returns:
        dict: Map of prefix to PTF ports that are connected to DUT output ports.
            {
                '192.168.0.0/21': [],
                '192.168.8.0/25': [[58 59] [62 63] [66 67] [70 71]],
                '192.168.16.0/25': [[58 59] [62 63] [66 67] [70 71]],
                ...
                '20c0:c2e8:0:80::/64': [[58 59] [62 63] [66 67] [70 71]],
                '20c1:998::/64': [[58 59] [62 63] [66 67] [70 71]],
                ...
            }
    """
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    fib_info = {}
    for asic_index, asic_cfg_facts in enumerate(dut_cfg_facts):

        asic = duthost.asic_instance(asic_index)

        asic.shell("{} redis-dump -d 0 -k 'ROUTE*' -y > /tmp/fib.{}.txt".format(asic.ns_arg, timestamp))
        duthost.fetch(src="/tmp/fib.{}.txt".format(timestamp), dest="/tmp/fib")

        po = asic_cfg_facts.get('PORTCHANNEL', {})
        ports = asic_cfg_facts.get('PORT', {})
        sub_interfaces = asic_cfg_facts.get('VLAN_SUB_INTERFACE', {})

        with open("/tmp/fib/{}/tmp/fib.{}.txt".format(duthost.hostname, timestamp)) as fp:
            fib = json.load(fp)
            for k, v in fib.items():
                skip = False

                prefix = k.split(':', 1)[1]
                ifnames = v['value']['ifname'].split(',')
                nh = v['value']['nexthop']

                oports = []
                for ifname in ifnames:
                    if po.has_key(ifname):
                        # ignore the prefix, if the prefix nexthop is not a frontend port
                        if 'members' in po[ifname]:
                            if 'role' in ports[po[ifname]['members'][0]] and ports[po[ifname]['members'][0]]['role'] == 'Int':
                                skip = True
                            else:
                                oports.append([str(duts_mg_facts['minigraph_ptf_indices'][x]) for x in po[ifname]['members']])
                    else:
                        if sub_interfaces.has_key(ifname):
                            oports.append([str(duts_mg_facts['minigraph_ptf_indices'][ifname.split('.')[0]])])
                        elif ports.has_key(ifname):
                            if 'role' in ports[ifname] and ports[ifname]['role'] == 'Int':
                                skip = True
                            else:
                                oports.append([str(duts_mg_facts['minigraph_ptf_indices'][ifname])])
                        else:
                            logger.info("Route point to non front panel port {}:{}".format(k, v))
                            skip = True

                # skip direct attached subnet
                if nh == '0.0.0.0' or nh == '::' or nh == "":
                    skip = True

                if not skip:
                    if prefix in fib_info:
                        fib_info[prefix] += oports
                    else:
                        fib_info[prefix] = oports
                # For single_asic device, add empty list for directly connected subnets
                elif skip and not duthost.is_multi_asic:
                    fib_info[prefix] = []

    return fib_info


def gen_fib_info_file(ptfhost, fib_info, filename):
    """Store FIB info dumped & parsed from database to temporary file, then copy the file to PTF host.

    Args:
        ptfhost (PTFHost): Instance of PTFHost for interacting with the PTF host.
        fib_info (dict): FIB info dumped and parsed from database.
        filename (str): Name of the target FIB info file on PTF host.
    """
    tmp_fib_info = tempfile.NamedTemporaryFile()
    for prefix, oports in fib_info.items():
        tmp_fib_info.write(prefix)
        if oports:
            for op in oports:
                tmp_fib_info.write(' [{}]'.format(' '.join(op)))
        else:
            tmp_fib_info.write(' []')
        tmp_fib_info.write('\n')
    tmp_fib_info.flush()
    ptfhost.copy(src=tmp_fib_info.name, dest=filename)


@pytest.fixture(scope='module')
def fib_info_files(duthosts, ptfhost, duts_running_config_facts, duts_minigraph_facts, tbinfo, request):
    """Get FIB info from database and store to text files on PTF host.

    For T2 topology, generate a single file to /root/fib_info_all_duts.txt to PTF host.
    For other topologies, generate one file for each duthost. File name pattern:
        /root/fib_info_dut<dut_index>.txt

    Args:
        duthosts (DutHosts): Instance of DutHosts for interacting with DUT hosts.
        ptfhost (PTFHost): Instance of PTFHost for interacting with the PTF host.
        duts_running_config_facts (dict): Running config facts of all DUT hosts.
        duts_minigraph_facts (dict): Minigraph facts of all DUT hosts.
        tbinfo (object): Instance of TestbedInfo.

    Returns:
        list: List of FIB info file names on PTF host.
    """
    duts_config_facts = duts_running_config_facts
    testname = request.node.name
    files = []
    if tbinfo['topo']['type'] != "t2":
        for dut_index, duthost in enumerate(duthosts):
            fib_info = get_fib_info(duthost, duts_config_facts[duthost.hostname], duts_minigraph_facts[duthost.hostname])
            if 'test_decap' in testname and 'backend' in tbinfo['topo']['name']:
                # if it is a storage backend topo and the testcase is test_decap
                # add default routes with empty nexthops as the prefix matching failover
                fib_info[u'0.0.0.0/0'] = []
                fib_info[u'::/0'] = []
            filename = '/root/fib_info_dut{}.txt'.format(dut_index)
            gen_fib_info_file(ptfhost, fib_info, filename)
            files.append(filename)
    else:
        fib_info = get_t2_fib_info(duthosts, duts_config_facts, duts_minigraph_facts)
        filename = '/root/fib_info_all_duts.txt'
        gen_fib_info_file(ptfhost, fib_info, filename)
        files.append(filename)

    return files


@pytest.fixture(scope='function')
def fib_info_files_per_function(duthosts, ptfhost, duts_running_config_facts, duts_minigraph_facts, tbinfo, request):
    """Get FIB info from database and store to text files on PTF host.

    For T2 topology, generate a single file to /root/fib_info_all_duts.txt to PTF host.
    For other topologies, generate one file for each duthost. File name pattern:
        /root/fib_info_dut<dut_index>.txt

    Args:
        duthosts (DutHosts): Instance of DutHosts for interacting with DUT hosts.
        ptfhost (PTFHost): Instance of PTFHost for interacting with the PTF host.
        duts_running_config_facts (dict): Running config facts of all DUT hosts.
        duts_minigraph_facts (dict): Minigraph facts of all DUT hosts.
        tbinfo (object): Instance of TestbedInfo.

    Returns:
        list: List of FIB info file names on PTF host.
    """
    duts_config_facts = duts_running_config_facts
    testname = request.node.name
    files = []
    if tbinfo['topo']['type'] != "t2":
        for dut_index, duthost in enumerate(duthosts):
            fib_info = get_fib_info(duthost, duts_config_facts[duthost.hostname], duts_minigraph_facts[duthost.hostname])
            if 'test_basic_fib' in testname and 'backend' in tbinfo['topo']['name']:
                # if it is a storage backend topology(bt0 or bt1) and testcase is test_basic_fib
                # add a default route as failover in the prefix matching
                fib_info[u'0.0.0.0/0'] = []
                fib_info[u'::/0'] = []
            filename = '/root/fib_info_dut_{0}_{1}.txt'.format(testname, dut_index)
            gen_fib_info_file(ptfhost, fib_info, filename)
            files.append(filename)
    else:
        fib_info = get_t2_fib_info(duthosts, duts_config_facts, duts_minigraph_facts)
        filename = '/root/fib_info_all_duts.txt'
        gen_fib_info_file(ptfhost, fib_info, filename)
        files.append(filename)

    return files

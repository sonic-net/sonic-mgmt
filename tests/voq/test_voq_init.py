"""Test initialization of VoQ objects, switch, system ports, router interfaces, neighbors, inband port."""
import json
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert

from tests.common.helpers.sonic_db import AsicDbCli, VoqDbCli
from voq_helpers import check_voq_remote_neighbor, get_sonic_mac
from voq_helpers import check_local_neighbor_asicdb, get_device_system_ports, get_inband_info
from voq_helpers import check_rif_on_sup, check_voq_neighbor_on_sup
from voq_helpers import dump_and_verify_neighbors_on_asic

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]


class TestVoqSwitch(object):
    SWITCH_ID_LIST = []

    def test_voq_switch_create(self, duthosts, enum_frontend_dut_hostname, enum_asic_index, all_cfg_facts):
        """Compare the config facts with the asic db for switch:
        * Verify ASIC_DB get all system ports referenced in configDB created on all hosts and ASICs.
        * Verify object creation and values of port attributes.
        """
        per_host = duthosts[enum_frontend_dut_hostname]
        asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
        cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

        dev_facts = cfg_facts['DEVICE_METADATA']['localhost']
        asicdb = AsicDbCli(asic)

        switchkey = asicdb.get_switch_key()
        logger.info("Checking switch %s", switchkey)
        check_list = {
            "max_cores": "SAI_SWITCH_ATTR_MAX_SYSTEM_CORES",
            "switch_id": "SAI_SWITCH_ATTR_SWITCH_ID"}
        for k in check_list:
            asicdb.get_and_check_key_value(switchkey, dev_facts[k], field=check_list[k])

        pytest_assert(dev_facts["switch_id"] not in TestVoqSwitch.SWITCH_ID_LIST,
                      "Switch ID: %s has been used more than once" % dev_facts["switch_id"])
        TestVoqSwitch.SWITCH_ID_LIST.append(dev_facts["switch_id"])

        asicdb.get_and_check_key_value(switchkey, "SAI_SWITCH_TYPE_VOQ", field="SAI_SWITCH_ATTR_TYPE")


def test_voq_system_port_create(duthosts, enum_frontend_dut_hostname, enum_asic_index, all_cfg_facts):
    """Compare the config facts with the asic db for system ports

    * Verify ASIC_DB get all system ports referenced in configDB created on all hosts and ASICs.
    * Verify object creation and values of port attributes.

    """
    per_host = duthosts[enum_frontend_dut_hostname]
    asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
    cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

    logger.info("Checking system ports on host: %s, asic: %s", per_host.hostname, asic.asic_index)

    dev_ports = get_device_system_ports(cfg_facts)
    asicdb = AsicDbCli(asic)
    sys_port_table = asicdb.dump(asicdb.ASIC_SYSPORT_TABLE)
    keylist = sys_port_table.keys()
    pytest_assert(len(keylist) == len(dev_ports.keys()),
                  "Found %d system port keys, %d entries in cfg_facts, not matching" % (
                      len(keylist), len(dev_ports.keys())))
    logger.info("Found %d system port keys, %d entries in cfg_facts, checking each.",
                len(keylist), len(dev_ports.keys()))
    for portkey in keylist:
        try:
            port_config_info = sys_port_table[portkey]['value']['SAI_SYSTEM_PORT_ATTR_CONFIG_INFO']
        except KeyError:
            # TODO: Need to check on behavior here.
            logger.warning("System port: %s had no SAI_SYSTEM_PORT_ATTR_CONFIG_INFO", portkey)
            continue

        port_data = json.loads(port_config_info)
        for cfg_port in dev_ports:
            if dev_ports[cfg_port]['system_port_id'] == port_data['port_id']:
                #             "switch_id": "0",
                #             "core_index": "1",
                #             "core_port_index": "6",
                #             "speed": "400000"
                pytest_assert(dev_ports[cfg_port]['switch_id'] == port_data[
                    'attached_switch_id'], "switch IDs do not match for port: %s" % portkey)
                pytest_assert(dev_ports[cfg_port]['core_index'] == port_data[
                    'attached_core_index'], "switch IDs do not match for port: %s" % portkey)
                pytest_assert(dev_ports[cfg_port]['core_port_index'] == port_data[
                    'attached_core_port_index'], "switch IDs do not match for port: %s" % portkey)
                pytest_assert(dev_ports[cfg_port]['speed'] == port_data[
                    'speed'], "switch IDs do not match for port: %s" % portkey)
                break
        else:
            logger.error("Could not find config entry for portkey: %s" % portkey)

    logger.info("Host: %s, Asic: %s all ports match all parameters", per_host.hostname, asic.asic_index)


def test_voq_local_port_create(duthosts, enum_frontend_dut_hostname, enum_asic_index, all_cfg_facts):
    """Compare the config facts with the asic db for local ports

    * Verify ASIC_DB has host interface information for all local ports on all cards and ASICs.
    * Verify host interfaces exist on host CLI (ifconfig).
    * Verify interfaces exist in show interfaces on the linecard.
    """

    per_host = duthosts[enum_frontend_dut_hostname]
    asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
    cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

    dev_ports = cfg_facts['PORT']

    asicdb = AsicDbCli(asic)
    hostif_table = asicdb.get_hostif_table(refresh=True)

    keylist = hostif_table.keys()
    pytest_assert(len(keylist) == len(dev_ports.keys()),
                  "Found %d hostif keys, %d entries in cfg_facts" % (len(keylist), len(dev_ports.keys())))
    logger.info("Found %s ports to check on host:%s, asic: %s.", len(dev_ports.keys()), per_host.hostname,
                asic.asic_index)

    show_intf = asic.show_interface(command="status", include_internal_intfs=True)['ansible_facts']
    for portkey in keylist:
        portkey = portkey.decode('unicode-escape')  # need to handle the hyphen in the inband port name
        port_name = hostif_table[portkey]['value']["SAI_HOSTIF_ATTR_NAME"].decode('unicode-escape')
        port_state = hostif_table[portkey]['value']["SAI_HOSTIF_ATTR_OPER_STATUS"]
        port_type = hostif_table[portkey]['value']["SAI_HOSTIF_ATTR_TYPE"]

        logger.info("Checking port: %s, state: %s", port_name, port_state)
        # "SAI_HOSTIF_ATTR_NAME": "Ethernet0",
        # "SAI_HOSTIF_ATTR_OBJ_ID": "oid:0x1000000000002",
        # "SAI_HOSTIF_ATTR_OPER_STATUS": "false",
        # "SAI_HOSTIF_ATTR_TYPE": "SAI_HOSTIF_TYPE_NETDEV"
        pytest_assert(port_type == "SAI_HOSTIF_TYPE_NETDEV", "Port %s is not type netdev" % portkey)
        if port_state == "true":
            pytest_assert(show_intf['int_status'][port_name]['oper_state'] == "up",
                          "Show interface state is down when it should be up")
        if port_state == "false":
            pytest_assert(show_intf['int_status'][port_name]['oper_state'] == "down",
                          "Show interface state is up when it should be down")

        if asic.namespace is None:
            cmd = "sudo ifconfig %s" % port_name
        else:
            cmd = "sudo ip netns exec %s ifconfig %s" % (asic.namespace, port_name)
        ifout = per_host.command(cmd)
        assert "not found" not in ifout['stdout_lines'][0], "Interface %s not found" % port_name
        if port_state == "true" and "RUNNING" in ifout['stdout_lines'][0]:
            logger.debug("Interface state is up and matches")
        elif port_state == "false" and "RUNNING" not in ifout['stdout_lines'][0]:
            logger.debug("Interface state is down and matches")
        else:
            raise AssertionError("Interface state does not match: %s %s", port_state, ifout['stdout_lines'][0])


def check_voq_interfaces(duthosts, per_host, asic, cfg_facts):
    """
    Checks router interfaces on a dut.

    Args:
        duthosts: The duthosts fixture
        per_host: Instance of MultiAsicSonic host to check.
        asic: Instance of SonicAsic to check,
        cfg_facts: Config facts for the frontend duthost/asic under test

    """
    logger.info("Check router interfaces on node: %s, asic: %d", per_host.hostname, asic.asic_index)

    dev_intfs = cfg_facts.get('INTERFACE', {})
    voq_intfs = cfg_facts.get('VOQ_INBAND_INTERFACE', [])
    dev_sysports = get_device_system_ports(cfg_facts)

    rif_ports_in_asicdb = []

    # intf_list = get_router_interface_list(dev_intfs)
    asicdb = AsicDbCli(asic)
    asicdb_rif_table = asicdb.dump(asicdb.ASIC_ROUTERINTF_TABLE)
    sys_port_table = asicdb.dump(asicdb.ASIC_SYSPORT_TABLE)
    asicdb_lag_table = asicdb.dump(asicdb.ASIC_LAG_TABLE + ":")

    if per_host.is_multi_asic and len(duthosts.supervisor_nodes) == 0:
        voqdb = VoqDbCli(per_host)
    else:
        voqdb = VoqDbCli(duthosts.supervisor_nodes[0])

    systemlagtable = voqdb.dump("SYSTEM_LAG_ID_TABLE")
    systemintftable = voqdb.dump("SYSTEM_INTERFACE")

    # asicdb_intf_key_list = asicdb.get_router_if_list()
    # Check each rif in the asicdb, if it is local port, check VOQ DB for correct RIF.
    # If it is on system port, verify slot/asic/port and OID match a RIF in VoQDB
    for rif in asicdb_rif_table.keys():
        rif_type = asicdb_rif_table[rif]['value']["SAI_ROUTER_INTERFACE_ATTR_TYPE"]
        if rif_type != "SAI_ROUTER_INTERFACE_TYPE_PORT":
            logger.info("Skip this rif: %s, it is not on a port: %s", rif, rif_type)
            continue
        else:
            portid = asicdb_rif_table[rif]['value']["SAI_ROUTER_INTERFACE_ATTR_PORT_ID"]
            logger.info("Process RIF %s, Find port with ID: %s", rif, portid)

        porttype = asicdb.get_rif_porttype(portid)
        logger.info("RIF: %s is of type: %s", rif, porttype)
        if porttype == 'hostif':
            # find the hostif entry to get the physical port the router interface is on.
            hostifkey = asicdb.find_hostif_by_portid(portid)
            hostif = asicdb.get_hostif_table(refresh=False)[hostifkey]['value']['SAI_HOSTIF_ATTR_NAME'].decode('unicode-escape')
            logger.info("RIF: %s is on local port: %s", rif, hostif)
            rif_ports_in_asicdb.append(hostif)
            if hostif not in dev_intfs and hostif not in voq_intfs:
                pytest.fail("Port: %s has a router interface, but it isn't in configdb." % portid)

            # check MTU and ethernet address
            pytest_assert(asicdb_rif_table[rif]['value']["SAI_ROUTER_INTERFACE_ATTR_MTU"] == cfg_facts['PORT'][hostif]['mtu'],
                          "MTU for rif %s is not %s" % (rif, cfg_facts['PORT'][hostif]['mtu']))
            intf_mac = get_sonic_mac(per_host, asic.asic_index, hostif)
            pytest_assert(asicdb_rif_table[rif]['value']["SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS"].lower() == intf_mac.lower(),
                          "MAC for rif %s is not %s" % (rif, intf_mac))

            sysport_info = {'slot': cfg_facts['DEVICE_METADATA']['localhost']['hostname'],
                            'asic': cfg_facts['DEVICE_METADATA']['localhost']['asic_name']}

            check_rif_on_sup(systemintftable, sysport_info['slot'], sysport_info['asic'], hostif)

        elif porttype == 'sysport':
            try:
                port_output = sys_port_table["ASIC_STATE:SAI_OBJECT_TYPE_SYSTEM_PORT:" + portid]['value']['SAI_SYSTEM_PORT_ATTR_CONFIG_INFO']
            except KeyError:
                # not a hostif or system port, log error and continue
                logger.error("Did not find OID %s in local or system tables" % portid)
                continue
            port_data = json.loads(port_output)
            for cfg_port in dev_sysports:
                if dev_sysports[cfg_port]['system_port_id'] == port_data['port_id']:
                    logger.info("RIF: %s is on remote port: %s", rif, cfg_port)
                    break
            else:
                raise AssertionError("Did not find OID %s in local or system tables" % portid)

            sys_slot, sys_asic, sys_port = cfg_port.split("|")
            check_rif_on_sup(systemintftable, sys_slot, sys_asic, sys_port)

        elif porttype == 'port':
            # this is the RIF on the inband port.
            inband = get_inband_info(cfg_facts)
            logger.info("RIF: %s is on local port: %s", rif, inband['port'])

            # check MTU and ethernet address
            pytest_assert(asicdb_rif_table[rif]['value']["SAI_ROUTER_INTERFACE_ATTR_MTU"] == cfg_facts['PORT'][inband['port']]['mtu'],
                          "MTU for rif %s is not %s" % (rif, cfg_facts['PORT'][inband['port']]['mtu']))
            intf_mac = get_sonic_mac(per_host, asic.asic_index, inband['port'])
            pytest_assert(asicdb_rif_table[rif]['value']["SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS"].lower() == intf_mac.lower(),
                          "MAC for rif %s is not %s" % (rif, intf_mac))

            sysport_info = {'slot': cfg_facts['DEVICE_METADATA']['localhost']['hostname'],
                            'asic': cfg_facts['DEVICE_METADATA']['localhost']['asic_name']}

            check_rif_on_sup(systemintftable, sysport_info['slot'], sysport_info['asic'], inband['port'])

        # TODO: Could be on a LAG
        elif porttype == 'lag':
            #lagid = asicdb.hget_key_value("%s:%s" % (AsicDbCli.ASIC_LAG_TABLE, portid), 'SAI_LAG_ATTR_SYSTEM_PORT_AGGREGATE_ID')
            lagid = asicdb_lag_table["%s:%s" % (AsicDbCli.ASIC_LAG_TABLE, portid)]['value']['SAI_LAG_ATTR_SYSTEM_PORT_AGGREGATE_ID']
            logger.info("RIF: %s is on system LAG: %s", rif, lagid)


            for lag, sysid in systemlagtable['SYSTEM_LAG_ID_TABLE']['value'].iteritems():
                if sysid == lagid:
                    logger.info("System LAG ID %s is portchannel: %s", lagid, lag)
                    break

            myslot = cfg_facts['DEVICE_METADATA']['localhost']['hostname']
            myasic = cfg_facts['DEVICE_METADATA']['localhost']['asic_name']
            if lag.startswith("%s|%s" % (myslot, myasic)):
                logger.info("Lag: %s is a local portchannel with a router interface.", lag)
                (s, a, lagname) = lag.split("|")
                pytest_assert(lagname in cfg_facts['PORTCHANNEL_INTERFACE'], "RIF Interface %s is in configdb.json but not in asicdb" % rif)

                check_rif_on_sup(systemintftable, myslot, myasic, lagname)

            else:
                logger.info("Lag: %s is a remote portchannel with a router interface.", lag)

    # Verify each RIF in config had a corresponding local port RIF in the asicDB.
    for rif in dev_intfs:
        if rif not in rif_ports_in_asicdb:
            raise AssertionError("Interface %s is in configdb.json but not in asicdb" % rif)

    logger.info("Interfaces %s are present in configdb.json and asicdb" % str(dev_intfs.keys()))


def test_voq_interface_create(duthosts, enum_frontend_dut_hostname, enum_asic_index, all_cfg_facts):
    """
    Verify router interfaces are created on all line cards and present in Chassis App Db.

    * Verify router interface creation on local ports in ASIC DB.
    * PORT_ID should match system port table and traced back to config_db.json, mac and MTU should match as well.
    * Verify SYSTEM_INTERFACE table in Chassis AppDb (redis-dump -h <ip> -p 6380 -d 12 on supervisor).
    * Verify creation interfaces with different MTUs in configdb.json.
    * Verify creation of different subnet masks in configdb.json.
    * Repeat with IPv4, IPv6, dual-stack.

    """

    per_host = duthosts[enum_frontend_dut_hostname]
    asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
    cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']
    check_voq_interfaces(duthosts, per_host, asic, cfg_facts)


def test_voq_neighbor_create(duthosts, enum_frontend_dut_hostname, enum_asic_index, nbrhosts,
                             all_cfg_facts, nbr_macs):
    """
    Verify neighbor entries are created on linecards for local and remote VMS.

    For local neighbors:
    * ARP/NDP should be resolved when BGP to adjacent VMs is established.
    * On local linecard, verify ASIC DB entries.
        * MAC address matches MAC of neighbor VM.
        * Router interface OID matches back to the correct interface and port the neighbor was learned on.
    * On local linecard, verify show arp/ndp, ip neigh commands.
        * MAC address matches MAC of neighbor VM.
    * On local linecard. verify neighbor table in appDB.
        * MAC address matches MAC of neighbor VM.
    * On supervisor card, verify SYSTEM_NEIGH table in Chassis AppDB (redis-dump -h <ip> -p 6380 -d 12 on supervisor).
        * Verify encap index and MAC address match between ASICDB the Chassis AppDB
    * Repeat with IPv4, IPv6, dual-stack.

    For remote neighbors:
    * When local neighbors are established as in the Local Neighbor testcase, corresponding entries will be established
      on all other line cards.  On each remote card, verify:
    * Verify ASIC DB entries on remote linecards.
        * Verify impose index=True in ASIC DB.
        * Verify MAC address in ASIC DB is the remote neighbor mac.
        * Verify encap index for ASIC DB entry matches Chassis App DB.
        * Verify router interface OID matches the interface the neighbor was learned on.
    * Verify on linecard CLI, show arp/ndp, ip neigh commands.
        * For inband port, MAC should be inband port mac in kernel table and LC appDb.
        * For inband vlan mode, MAC will be remote ASIC mac in kernel table and LC appdb.
    * Verify neighbor table in linecard appdb.
    * Verify static route is installed in kernel routing table with /32 (or /128 for IPv6) for neighbor entry.
    * Repeat with IPv4, IPv6, dual-stack.

    """
    per_host = duthosts[enum_frontend_dut_hostname]
    asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
    cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

    logger.info("Checking local neighbors on host: %s, asic: %s", per_host.hostname, asic.asic_index)
    if 'BGP_NEIGHBOR' in cfg_facts:
        neighs = cfg_facts['BGP_NEIGHBOR']
    else:
        logger.info("No local neighbors for host: %s/%s, skipping", per_host.hostname, asic.asic_index)
        return

    dump_and_verify_neighbors_on_asic(duthosts, per_host, asic, neighs, nbrhosts, all_cfg_facts, nbr_macs)


def test_voq_inband_port_create(duthosts, enum_frontend_dut_hostname, enum_asic_index, all_cfg_facts):
    """
    Test inband port creation.

    These steps are covered by previous test cases:
        * On each linecard, verify inband ports are present in ASICDB.
        * On each linecard, verify inband router interfaces are present in ASICDB
        * On supervisor card, verify inband router interfaces are present in Chassis App DB

    This test function will cover:
        * On each linecard, verify permanent neighbors for all inband ports.
        * On each linecard, verify kernel routes for all inband ports.
        * Repeat with IPv4, IPv6, dual-stack.


    """
    per_host = duthosts[enum_frontend_dut_hostname]
    asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
    cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

    inband_info = get_inband_info(cfg_facts)
    if inband_info == {}:
        logger.info("No inband configuration on this ASIC: %s/%s, skipping", per_host.hostname, asic.asic_index)
        return
    inband_mac = get_sonic_mac(per_host, asic.asic_index, inband_info['port'])

    inband_ips = []
    if 'ipv6_addr' in inband_info:
        inband_ips.append(inband_info['ipv6_addr'])
    if 'ipv4_addr' in inband_info:
        inband_ips.append(inband_info['ipv4_addr'])

    for neighbor_ip in inband_ips:

        host = per_host
        neighbor_mac = inband_mac
        interface = inband_info['port']

        logger.info("Check local neighbor on host %s, asic %s for %s/%s via port: %s", host.hostname,
                    str(asic.asic_index),
                    neighbor_ip, neighbor_mac, interface)

        asic_dict = check_local_neighbor_asicdb(asic, neighbor_ip, neighbor_mac)
        encap_idx = asic_dict['encap_index']

        sysport_info = {'slot': cfg_facts['DEVICE_METADATA']['localhost']['hostname'],
                        'asic': cfg_facts['DEVICE_METADATA']['localhost']['asic_name']}

        for sup in duthosts.supervisor_nodes:
            check_voq_neighbor_on_sup(sup, sysport_info['slot'], sysport_info['asic'], interface, neighbor_ip,
                                      encap_idx, inband_mac)

        # Check the neighbor entry on each remote linecard
        for rem_host in duthosts.frontend_nodes:

            for rem_asic in rem_host.asics:
                if rem_host == per_host and rem_asic == asic:
                    # skip remote check on local host
                    continue
                rem_cfg_facts = all_cfg_facts[rem_host.hostname][rem_asic.asic_index]['ansible_facts']
                remote_inband_info = get_inband_info(rem_cfg_facts)
                if remote_inband_info == {}:
                    logger.info("No inband configuration on this asic: %s/%s, will be skipped.", rem_host.hostname,
                                rem_asic.asic_index)
                    continue
                remote_inband_mac = get_sonic_mac(rem_host, rem_asic.asic_index, remote_inband_info['port'])
                check_voq_remote_neighbor(rem_host, rem_asic, neighbor_ip, inband_mac,
                                          remote_inband_info['port'],
                                          encap_idx, remote_inband_mac)

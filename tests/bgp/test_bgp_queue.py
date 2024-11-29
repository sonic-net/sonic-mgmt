import time
import pytest
import logging

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def clear_queue_counters(asichost):
    asichost.command("sonic-clear queuecounters")


def get_queue_counters(asichost, port, queue):
    """
    Return the counter for a given queue in given port
    """
    cmd = "show queue counters {}".format(port)
    output = asichost.command(cmd)['stdout_lines']
    txq = "UC{}".format(queue)
    for line in output:
        fields = line.split()
        if fields[1] == txq:
            return int(fields[2].replace(',', ''))
    return -1


def test_bgp_queues(duthosts, enum_frontend_dut_hostname, enum_asic_index, tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    asichost = duthost.asic_instance(enum_asic_index)
    clear_queue_counters(asichost)
    time.sleep(10)
    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)

    arp_dict = {}
    ndp_dict = {}
    processed_intfs = set()
    show_arp = asichost.command('show arp')
    show_ndp = asichost.command('show ndp')
    for arp_entry in show_arp['stdout_lines']:
        items = arp_entry.split()
        if (len(items) != 4):
            continue
        ip = items[0]
        iface = items[2]
        arp_dict[ip] = iface
    for ndp_entry in show_ndp['stdout_lines']:
        items = ndp_entry.split()
        if (len(items) != 5):
            continue
        ip = items[0]
        iface = items[2]
        ndp_dict[ip] = iface

    for k, v in list(bgp_facts['bgp_neighbors'].items()):
        # Only consider established bgp sessions
        if v['state'] == 'established':
            # For "peer group" if it's internal it will be "INTERNAL_PEER_V4" or "INTERNAL_PEER_V6"
            # or "VOQ_CHASSIS_PEER_V4" or "VOQ_CHASSIS_PEER_V6" for VOQ_CHASSIS
            # If it's external it will be "RH_V4", "RH_V6", "AH_V4", "AH_V6", ...
            # Skip internal neighbors for VOQ_CHASSIS until BRCM fixes iBGP traffic in 2024011
            if ("INTERNAL" in v["peer group"] or 'VOQ_CHASSIS' in v["peer group"]) and \
                    duthost.get_facts().get('modular_chassis'):
                # Skip iBGP neighbors since we only want to verify eBGP
                continue
            assert (k in arp_dict.keys() or k in ndp_dict.keys())
            if k in arp_dict:
                ifname = arp_dict[k].split('.', 1)[0]
            else:
                ifname = ndp_dict[k].split('.', 1)[0]
            if ifname in processed_intfs:
                continue
            if (ifname.startswith("PortChannel")):
                for port in mg_facts['minigraph_portchannels'][ifname]['members']:
                    logger.info("PortChannel '{}' : port {}".format(ifname, port))
                    for q in range(0, 7):
                        assert (get_queue_counters(asichost, port, q) == 0)
            else:
                logger.info(ifname)
                for q in range(0, 7):
                    assert (get_queue_counters(asichost, ifname, q) == 0)
            processed_intfs.add(ifname)

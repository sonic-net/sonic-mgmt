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


def get_all_ports_queue_counters(asichost, queue_type_prefix="UC"):
    """
    Fetch queue counters for ALL ports in a single command.
    Returns a dict: {port_name: {queue_num: count, ...}, ...}
    Example: {'Ethernet0': {0: 0, 1: 0, ...}, 'Ethernet4': {0: 0, 1: 0, ...}}
    """
    cmd = "show queue counters"
    output = asichost.command(cmd, new_format=True)['stdout_lines']
    counters = {}
    for line in output:
        fields = line.split()
        if len(fields) < 3:
            continue
        port_name = fields[0]
        queue_type = fields[1]
        if port_name not in counters:
            counters[port_name] = {}
        if queue_type.startswith(queue_type_prefix):
            try:
                queue_num = int(queue_type[len(queue_type_prefix):])
                counters[port_name][queue_num] = int(fields[2].replace(',', ''))
            except (ValueError, IndexError):
                continue
    return counters


def assert_queue_counter_zero(queue_counters, port_name, queue_start=0, queue_end=6):
    for q in range(queue_start, queue_end + 1):
        counter_value = queue_counters.get(q, -1)
        assert counter_value == 0, (
            "Queue counter for port '{}' queue {} is not zero. Value: {}"
        ).format(port_name, q, counter_value)


def test_bgp_queues(duthosts, enum_frontend_dut_hostname, enum_asic_index, tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    asichost = duthost.asic_instance(enum_asic_index)
    clear_queue_counters(asichost)
    time.sleep(10)
    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)

    all_ports_queue_counters = get_all_ports_queue_counters(asichost, queue_type_prefix="UC")
    if not all_ports_queue_counters:
        pytest.skip("No queue counters found on the device.")

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
        # For "peer group" if it's internal it will be "INTERNAL_PEER_V4" or "INTERNAL_PEER_V6"
        # or "VOQ_CHASSIS_PEER_V4" or "VOQ_CHASSIS_PEER_V6" for VOQ_CHASSIS
        # If it's external it will be "RH_V4", "RH_V6", "AH_V4", "AH_V6", ...
        # Skip internal neighbors for VOQ_CHASSIS until BRCM fixes iBGP traffic in 2024011
        if ("INTERNAL" in v["peer group"] or 'VOQ_CHASSIS' in v["peer group"]):
            # Skip iBGP neighbors since we only want to verify eBGP
            continue
        # Only consider established bgp sessions
        if v['state'] == 'established':

            assert (k in arp_dict.keys() or k in ndp_dict.keys()), (
                "BGP neighbor IP '{}' not found in either ARP or NDP tables.\n"
                "- ARP table: {}\n"
                "- NDP table: {}"
            ).format(k, arp_dict, ndp_dict)

            if k in arp_dict:
                ifname = arp_dict[k].split('.', 1)[0]
            else:
                ifname = ndp_dict[k].split('.', 1)[0]
            if ifname in processed_intfs:
                continue
            if ifname.startswith("PortChannel"):
                for port in mg_facts['minigraph_portchannels'][ifname]['members']:
                    logger.info("PortChannel '{}' : port {}".format(ifname, port))
                    per_port_queue_counters = all_ports_queue_counters.get(port, {})
                    if not per_port_queue_counters:
                        logger.warning("No queue counters found for port '{}'".format(port))
                    else:
                        assert_queue_counter_zero(per_port_queue_counters, port, 0, 6)
            else:
                logger.info(ifname)
                per_iface_queue_counters = all_ports_queue_counters.get(ifname, {})
                if not per_iface_queue_counters:
                    logger.warning("No queue counters found for interface '{}'".format(ifname))
                else:
                    assert_queue_counter_zero(per_iface_queue_counters, ifname, 0, 6)
            processed_intfs.add(ifname)

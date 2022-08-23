"""Utils to verify traffic between ToR and server."""
import contextlib
import logging
import tempfile
import sys
import time

from io import BytesIO
from ptf.dataplane import match_exp_pkt
from scapy.all import sniff
from scapy.packet import ls


@contextlib.contextmanager
def dump_intf_packets(ansible_host, iface, pcap_save_path, dumped_packets,
                      pcap_filter=None, cleanup_pcap=True):
    """
    @summary: Dump packets of the interface and save to a file.

    @ansible_host: the ansible host object.
    @iface: interface to be sniffed on.
    @pcap_save_path: packet capture file save path.
    @dumped_packets: a list to store the dumped packets.
    @pcap_filter: pcap filter used by tcpdump.
    @cleanup_pcap: True to remove packet capture file.
    """

    start_pcap = "tcpdump --immediate-mode -i %s -w %s" % (iface, pcap_save_path)
    if pcap_filter:
        start_pcap += (" " + pcap_filter)
    start_pcap = "nohup %s > /dev/null 2>&1 & echo $!" % start_pcap
    pid = ansible_host.shell(start_pcap)["stdout"]
    # sleep to let tcpdump starts to capture
    time.sleep(1)
    try:
        yield
    finally:
        ansible_host.shell("kill -s 2 %s" % pid)
        with tempfile.NamedTemporaryFile() as temp_pcap:
            ansible_host.fetch(src=pcap_save_path, dest=temp_pcap.name, flat=True)
            packets = sniff(offline=temp_pcap.name)
            dumped_packets.extend(packets)
        if cleanup_pcap:
            ansible_host.file(path=pcap_save_path, state="absent")


class ServerTrafficMonitor(object):
    """Monit traffic between DUT and server."""

    VLAN_INTERFACE_TEMPLATE = "{external_port}.{vlan_id}"

    def __init__(self, duthost, ptfhost, vmhost, tbinfo, dut_iface, conn_graph_facts, exp_pkt, existing=True, is_mocked=False):
        """
        @summary: Initialize the monitor.

        @duthost: duthost object.
        @ptfhost: ptfhost object that represent the ptf docker.
        @vmhost: vmhost object that represent the vm host server.
        @tbinfo: testbed info.
        @dut_iface: the interface on duthost selected to be monitored.
        @conn_graph_facts: connection graph data.
        @exp_pkt: the expected packet to be matched with packets monitored,
                  should be a `ptf.mask.Mask` object.
        @existing: True to expect to find a match for `exp_pkt` while False to
                   expect to not find a match for `exp_pkt`.
        @is_mocked: True that it is a mocked dualtor testbed.
        """
        self.duthost = duthost
        self.dut_iface = dut_iface
        self.exp_pkt = exp_pkt
        self.ptfhost = ptfhost
        self.vmhost = vmhost
        self.tbinfo = tbinfo
        self.conn_graph_facts = conn_graph_facts
        self.captured_packets = []
        self.matched_packets = []
        if is_mocked:
            mg_facts = self.duthost.get_extended_minigraph_facts(self.tbinfo)
            ptf_iface = "eth%s" % mg_facts['minigraph_ptf_indices'][self.dut_iface]
            self.dump_utility = dump_intf_packets(
                ptfhost,
                ptf_iface,
                tempfile.NamedTemporaryFile().name,
                self.captured_packets
            )
        else:
            vmhost_iface = self._find_vmhost_vlan_interface()
            self.dump_utility = dump_intf_packets(
                vmhost,
                vmhost_iface,
                tempfile.NamedTemporaryFile().name,
                self.captured_packets
            )
        self.existing = existing

    @staticmethod
    def _list_layer_str(packet):
        """Return list layer output string."""
        _stdout, sys.stdout = sys.stdout, BytesIO()
        try:
            ls(packet)
            return sys.stdout.getvalue()
        finally:
            sys.stdout = _stdout

    def _find_vmhost_vlan_interface(self):
        """Find the vmhost vlan interface that will be sniffed on."""
        device_port_vlans = self.conn_graph_facts["device_port_vlans"][self.duthost.hostname]
        vlan_id = device_port_vlans[self.dut_iface]["vlanlist"][0]
        return self.VLAN_INTERFACE_TEMPLATE.format(external_port=self.vmhost.external_port, vlan_id=vlan_id)

    def __enter__(self):
        self.captured_packets[:] = []
        self.matched_packets[:] = []
        self.dump_utility.__enter__()

    def __exit__(self, exc_type, exc_value, traceback):
        self.dump_utility.__exit__(exc_type, exc_value, traceback)
        logging.info("the expected packet:\n%s", str(self.exp_pkt))
        self.matched_packets = [p for p in self.captured_packets if match_exp_pkt(self.exp_pkt, p)]
        logging.info("received %d matched packets", len(self.matched_packets))
        if self.matched_packets:
            logging.info(
                "display the most recent matched captured packet:\n%s",
                self._list_layer_str(self.matched_packets[-1])
            )
        if self.existing and not self.matched_packets:
            raise ValueError("Failed to find expected packet.")
        if not self.existing and self.matched_packets:
            raise ValueError("Found expected packet.")

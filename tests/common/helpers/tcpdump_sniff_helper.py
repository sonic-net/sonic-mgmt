import time
import logging
import scapy.all as scapyall


class TcpdumpSniffHelper(object):

    def __init__(self, ptfadapter, duthost, ptfhost, pcap_path="/tmp/capture.pcap"):
        self.ptfadpater = ptfadapter
        self.duthost = duthost
        self.ptfhost = ptfhost
        self._pcap_path = pcap_path
        self._tcpdump_filter = 'ip or ip6'
        self._out_direct_ifaces = []
        self._in_direct_ifaces = []
        self._bi_direct_ifaces = []
        self._total_ifaces = []

    @property
    def tcpdump_filter(self):
        return self._tcpdump_filter

    @tcpdump_filter.setter
    def tcpdump_filter(self, value):
        self._tcpdump_filter = value

    @property
    def out_direct_ifaces(self):
        return self._out_direct_ifaces

    @out_direct_ifaces.setter
    def out_direct_ifaces(self, value):
        self._out_direct_ifaces = list(set(value))

    @property
    def in_direct_ifaces(self):
        return self._in_direct_ifaces

    @in_direct_ifaces.setter
    def in_direct_ifaces(self, value):
        self._in_direct_ifaces = list(set(value))

    @property
    def bi_direct_ifaces(self):
        return self._bi_direct_ifaces

    @bi_direct_ifaces.setter
    def bi_direct_ifaces(self, value):
        self._bi_direct_ifaces = list(set(value))

    @property
    def pcap_path(self):
        return self._pcap_path

    def update_total_ifaces(self):
        self._total_ifaces = list(set(self._out_direct_ifaces + self._in_direct_ifaces + self._bi_direct_ifaces))

    def start_dump_process(self, host, iface, direction="inout"):
        """
        Start tcpdump on specific interface and save data to pcap file
        """
        iface_pcap_path = '{}_{}'.format(self.pcap_path, iface)
        if host is self.ptfhost:
            iface = 'eth' + str(iface)
        cmd = "tcpdump -i {} '{}' -w {} --immediate-mode --direction {} -U".format(iface, self._tcpdump_filter,
                                                                                   iface_pcap_path, direction)
        logging.info('Tcpdump sniffer starting on iface: {} direction: {}'.format(iface, direction))
        if host is self.duthost:
            cmd = "sudo " + cmd
        host.shell(self.run_background_cmd(cmd))

    def run_background_cmd(self, command):
        return "nohup " + command + " &"

    def start_sniffer(self, host='ptf'):
        """
        Start tcpdump sniffer
        """
        host = self.ptfhost if host == 'ptf' else self.duthost
        logging.info("Tcpdump sniffer starting")
        for iface in self.out_direct_ifaces:
            self.start_dump_process(host, iface, "out")
        for iface in self.in_direct_ifaces:
            self.start_dump_process(host, iface, "in")
        for iface in self.bi_direct_ifaces:
            self.start_dump_process(host, iface)

    def stop_sniffer(self, host='ptf'):
        """
        Stop tcpdump sniffer
        """
        cmd = "killall -s SIGINT tcpdump"
        host = self.ptfhost if host == 'ptf' else self.duthost
        time.sleep(2)  # Wait for switch and server tcpdump packet processing
        logging.info("Tcpdump sniffer stopping")
        logging.info("Killed all tcpdump processes by SIGINT")
        if host is self.duthost:
            host.shell('sudo ' + cmd)
            self.copy_pcaps_to_ptf()
        else:
            host.shell(cmd)
        self.create_single_pcap()
        logging.info("Copy {} from ptf docker to ngts docker".format(self.pcap_path))
        self.ptfhost.shell("chmod 777 {}".format(self.pcap_path))
        logging.info("Copy file {} from ptf docker to ngts docker".format(self.pcap_path))
        self.ptfhost.fetch(src=self.pcap_path, dest=self.pcap_path, flat=True)

    def copy_pcaps_to_ptf(self):
        self.update_total_ifaces()
        for iface in self._total_ifaces:
            iface_pcap_path = '{}_{}'.format(self.pcap_path, iface)
            logging.info("Copy {} from switch to ptf docker to do further operation".format(iface_pcap_path))
            self.duthost.fetch(src=iface_pcap_path, dest=iface_pcap_path, flat=True)
            self.ptfhost.copy(src=iface_pcap_path, dest=iface_pcap_path)
            logging.info("Remove {} at DUT".format(iface_pcap_path))
            self.duthost.shell("rm -f {}".format(iface_pcap_path))

    def sniffer_result(self):
        capture_packets = scapyall.rdpcap(self.pcap_path)
        logging.info("Number of all packets captured: {}".format(len(capture_packets)))
        return capture_packets

    def create_single_pcap(self):
        """
        Merge all pcaps from each interface into single pcap file
        """
        pcapng_full_capture = self.merge_pcaps()
        self.convert_pcapng_to_pcap(pcapng_full_capture)
        logging.info('Pcap files merged into single pcap file: {}'.format(self.pcap_path))

    def convert_pcapng_to_pcap(self, pcapng_full_capture):
        """
        Convert pcapng file into pcap. We can't just merge all in pcap,
        mergecap can merge multiple files only into pcapng format
        """
        cmd = "mergecap -F pcap -w {} {}".format(self.pcap_path, pcapng_full_capture)
        logging.info('Converting pcapng file into pcap file')
        self.ptfhost.shell(cmd)
        logging.info('Pcapng file converted into pcap file')
        self.ptfhost.shell("rm -f {}".format(pcapng_full_capture))

    def merge_pcaps(self):
        """
        Merge all pcaps into one, format: pcapng
        """
        pcapng_full_capture = '{}.pcapng'.format(self.pcap_path)
        cmd = "mergecap -w {}".format(pcapng_full_capture)
        ifaces_pcap_files_list = []
        self.update_total_ifaces()
        for iface in self._total_ifaces:
            pcap_file_path = '{}_{}'.format(self.pcap_path, iface)
            res = self.ptfhost.shell("ls -l {}".format(pcap_file_path), module_ignore_errors=True)
            if res["rc"] == 0:
                cmd += ' ' + (pcap_file_path)
                ifaces_pcap_files_list.append(pcap_file_path)

        logging.info('Starting merge pcap files')
        self.ptfhost.shell(cmd)
        logging.info('Pcap files merged into tmp pcapng file')
        for pcap_file in ifaces_pcap_files_list:
            self.ptfhost.shell("rm -f {}".format(pcap_file))

        return pcapng_full_capture

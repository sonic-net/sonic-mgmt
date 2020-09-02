import os
import sys
import time
import traceback
import threading

from packet import ScapyPacket
from or_event import OrEvent
from utils import Utils
from logger import Logger

def tobytes(s):
    if sys.version_info[0] < 3:
        return buffer(s)
    return s.encode()

def isLinkUp(intf, dbg = False):
    flags_path = "/sys/class/net/{}/operstate".format(intf)
    if os.path.isfile(flags_path):
      if dbg:
        os.system("ifconfig %s" % (intf))
      with open(flags_path, 'r') as fp:
        if fp.read().strip() != 'down':
          return True
    return False

class ScapyDriver(object):
    def __init__(self, port, dry=False, dbg=0, logger=None):
        self.port = port
        self.dry = dry
        self.dbg = dbg
        self.finished = False
        self.logger = logger or Logger()
        self.utils = Utils(self.dry, logger=self.logger)
        self.iface = port.iface
        self.packet = ScapyPacket(port.iface, dry=self.dry, dbg=self.dbg,
                                  logger=self.logger)
        self.rxInit()
        self.txInit()
        self.statState.set()

    def __del__(self):
        self.logger.debug("ScapyDriver {} exiting...".format(self.iface))
        self.cleanup()
        del self.packet

    def cleanup(self):
        print("ScapyDriver {} cleanup...".format(self.iface))
        self.finished = True
        self.captureState.clear()
        self.statState.clear()
        self.txState.clear()
        self.protocolState.clear()
        self.packet.cleanup()

    def rxInit(self):
        self.captureQueueInit()
        self.captureState = threading.Event()
        self.captureState.clear()
        self.protocolState = threading.Event()
        self.protocolState.clear()
        self.statState = threading.Event()
        self.statState.clear()
        self.rxThread = threading.Thread(target=self.rxThreadMain, args=())
        self.rxThread.daemon = True
        self.rxThread.start()

    def captureQueueInit(self):
        self.pkts_captured = []

    def startCapture(self):
        self.logger.debug("start-cap: {}".format(self.iface))
        self.pkts_captured = []
        self.captureState.set()

    def stopCapture(self):
        self.logger.debug("stop-cap: {}".format(self.iface))
        self.captureState.clear()
        time.sleep(1)
        return len(self.pkts_captured)

    def clearCapture(self):
        self.logger.debug("clear-cap: {}".format(self.iface))
        self.captureState.clear()
        time.sleep(3)
        self.pkts_captured = []
        return len(self.pkts_captured)

    def getCapture(self):
        self.logger.debug("get-cap: {}".format(self.iface))
        retval = []
        for pkt in self.pkts_captured:
            (data, hex_bytes) = (str(pkt), [])
            for index in range(len(data)):
                hex_bytes.append("%02X"% ord(data[index]))
            retval.append(hex_bytes)
        return retval

    def rx_any_enable(self):
        return self.captureState.is_set() or self.statState.is_set() or self.protocolState.is_set()

    def rxThreadMain(self):
        while not self.finished:
            # wait till captures or stats collection is enabled
            self.logger.debug("RX Thread {} start {}/{}/{}".format(self.iface,
                self.captureState.is_set(), self.statState.is_set(), self.protocolState.is_set()))
            while not self.rx_any_enable():
                time.sleep(1)
                OrEvent(self.captureState, self.statState, self.protocolState).wait()

            # read packets
            while self.rx_any_enable():
                try:
                    packet = self.packet.readp(iface=self.iface)
                    if packet:
                        self.handle_recv(None, packet)
                except Exception as e:
                    if str(e) != "[Errno 100] Network is down":
                        self.logger.debug(e, traceback.format_exc())
                    self.logger.debug("Driver(%s): '%s' - ignoring", self.iface, str(e))
                    while self.rx_any_enable() and isLinkUp(self.iface) == False:
                        time.sleep(1)

    def handle_stats(self, packet):
        pktlen = 0 if not packet else len(packet)
        framesReceived = self.port.incrStat('framesReceived')
        self.port.incrStat('bytesReceived', pktlen)
        if self.dbg > 2:
            self.logger.debug("{} framesReceived: {}".format(self.iface, framesReceived))
        if pktlen > 1518:
            self.port.incrStat('oversizeFramesReceived')
        for stream in self.port.track_streams:
            if self.packet.match_stream(stream, packet):
                stream.incrStat('framesReceived')
                stream.incrStat('bytesReceived', pktlen)

    def handle_capture(self, packet):
        self.pkts_captured.append(packet)

    def handle_recv(self, hdr, packet):
        if self.statState.is_set():
            self.handle_stats(packet)
        if self.captureState.is_set():
            self.handle_capture(packet)

    def txInit(self):
        self.txState = threading.Event()
        self.txState.clear()
        self.txStateAck = threading.Event()
        self.txStateAck.clear()
        self.txThread = threading.Thread(target=self.txThreadMain, args=())
        self.txThread.daemon = True
        self.txThread.start()

    def startTransmit(self, **kws):
        self.logger.debug("start-tx: {} {}".format(self.iface, kws))
        duration = self.utils.intval(kws, 'duration', 0)
        non_continuous = False

        # enable selected streams
        handle = kws.get('handle', None)
        if not handle:
            handles = self.port.streams.keys()
        else:
            handles = self.utils.make_list(handle)

        for stream_id, stream in self.port.streams.items():
            stream.enable2 = bool(stream_id in handles)
            if stream.kws.get("transmit_mode", "continuous") != "continuous":
                non_continuous = True

        # signal the start
        self.logger.debug("signal-tx: {} {}".format(self.iface, kws))
        self.txStateAck.clear()
        self.txState.set()

        # wait for first packet to be sent
        self.txStateAck.wait(10)
        self.logger.debug("start-tx-ack: {} {}".format(self.iface, kws))

        # wait for max 30 seconds to finish
        if non_continuous:
            for check in range(30):
                if not self.txState.is_set():
                    break
        elif duration > 0:
            self.logger.debug("waiting for duration: {}".format(duration))
            time.sleep(duration)
            self.txState.clear()
        else:
            self.logger.debug("waiting 3 sec")
            time.sleep(3)

        self.logger.debug("start-tx-finished: {} {}".format(self.iface, kws))

    def stopTransmit(self, **kws):

        # disable selected streams
        handle = kws.get('handle', None)
        if handle:
            for stream_id, stream in self.port.streams.items():
                if not handle or stream_id == handle:
                    stream.enable2 = False
            return

        if not self.txState.is_set():
            return
        self.logger.debug("stop-tx: {}".format(self.iface))
        self.txState.clear()
        for index in range(10):
            time.sleep(1)
            if not self.txState.is_set():
                break

    def clear_stats(self):
        self.packet.clear_stats()

    def txThreadMain(self):
        while not self.finished:
            while not self.txState.is_set():
                self.logger.debug("txThreadMain {} Wait".format(self.iface))
                self.txState.wait()
            try:
                self.txThreadMainInner()
            except Exception as e:
                self.logger.log_exception(e, traceback.format_exc())
            self.txState.clear()

    def txThreadMainInner(self):
        self.logger.debug("txThreadMainInner {} start {}".format(self.iface, self.port.streams))
        pwa_list = []
        try:
            for stream in self.port.streams.values():
                self.logger.debug(" start {} {}/{}".format(stream.stream_id, stream.enable, stream.enable2))
                if stream.enable and stream.enable2:
                    pwa = self.packet.build_first(stream)
                    pwa.tx_time = time.clock()
                    pwa_list.append(pwa)
        except Exception as exp:
            self.logger.log_exception(exp, traceback.format_exc())

        if not pwa_list:
            self.logger.debug("txThreadMainInner {} Nothing Todo".format(self.iface))
            self.txStateAck.set()
            return

        # signal first packet ready
        self.txStateAck.set()

        tx_count = 0
        while (self.txState.is_set()):
            pwa_list.sort(key=self.pwa_sort)
            pwa_next_list = []
            for pwa in pwa_list:
                self.pwa_wait(pwa)
                try:
                    send_start_time = time.clock()
                    pkt = self.send_packet(pwa)
                    if pwa.stream.track_port:
                        pwa.stream.track_pkts.append(pkt)
                    bytesSent = len(pkt)
                    send_time = time.clock() - send_start_time
                    framesSent = self.port.incrStat('framesSent')
                    self.port.incrStat('bytesSent', bytesSent)
                    if self.dbg > 2:
                        self.logger.debug("{} framesSent: {}".format(self.iface, framesSent))
                    pwa.stream.incrStat('framesSent')
                    pwa.stream.incrStat('bytesSent', bytesSent)
                    tx_count = tx_count + 1
                except Exception as e:
                    self.logger.log_exception(e, traceback.format_exc())
                    pwa.stream.enable2 = False
                else:
                    pps = pwa.rate_pps
                    build_start_time = time.clock()
                    pwa = self.packet.build_next(pwa)
                    if not pwa: continue
                    build_time = time.clock() - build_start_time
                    if pps > self.packet.max_rate_pps: pps = self.packet.max_rate_pps
                    pwa.tx_time = time.clock() + 1.0/float(pps) - build_time - send_time
                    pwa_next_list.append(pwa)
            pwa_list = pwa_next_list
        self.logger.debug("txThreadMainInner Completed {}".format(tx_count))

    def pwa_sort(self, pwa):
        return pwa.tx_time

    def pwa_wait(self, pwa):
        delay = pwa.tx_time - time.clock()
        if self.dbg > 1:
            self.logger.debug("stream: {} delay: {} pps: {}".format(pwa.stream.stream_id, delay, pwa.rate_pps))
        if delay <= 0:
            # yield
            time.sleep(0)
        elif delay > 1.0/10:
            self.utils.msleep(delay * 1000, 10)
        elif delay > 1.0/100:
            self.utils.msleep(delay * 1000, 1)
        elif delay > 1.0/200:
            self.utils.usleep(delay * 1000 * 1000, 100)
        elif delay > 1.0/500:
            self.utils.usleep(delay * 1000 * 1000, 10)
        else:
            self.utils.usleep(delay * 1000 * 1000)

    def send_packet(self, pwa):
        return self.packet.send_packet(pwa, self.iface)

    def createInterface(self, intf):
        return self.packet.if_create(intf)

    def deleteInterface(self, intf):
        return self.packet.if_delete(intf)

    def ping(self, intf, ping_dst, index=0):
        return self.packet.ping(intf, ping_dst, index)

    def send_arp(self, intf, index=0):
        return self.packet.send_arp(intf, index)

    def config_bgp(self, enable, intf):
        return self.packet.config_bgp(enable, intf)

    def config_igmp(self, mode, intf, host):
        return self.packet.config_igmp(mode, intf, host)


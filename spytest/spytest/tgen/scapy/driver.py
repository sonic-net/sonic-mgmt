import os
import time
import traceback
import threading

from packet import ScapyPacket
from or_event import OrEvent
from utils import Utils
from logger import Logger

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
        self.errs = []
        self.finished = False
        self.logger = logger or Logger()
        self.utils = Utils(self.dry, logger=self.logger)
        self.iface = port.iface
        self.iface_status = None
        self.packet = ScapyPacket(port.iface, dry=self.dry, dbg=self.dbg,
                                  logger=self.logger)
        self.rxInit()
        self.txInit()
        self.statState.set()

    def __del__(self):
        self.logger.debug("ScapyDriver {} exiting...".format(self.iface))
        self.cleanup()
        del self.packet

    def get_alerts(self):
        errs = []
        errs.extend(self.errs)
        errs.extend(self.packet.get_alerts())
        self.errs = []
        return errs

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
        #self.linkThread = threading.Thread(target=self.linkThreadMain, args=())
        #self.linkThread.daemon = True
        #self.linkThread.start()
        self.linkThread = None

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
                    while self.rx_any_enable() and not self.is_up():
                        time.sleep(1)

    def is_up(self):
        if self.linkThread:
            return bool(self.iface_status)
        return isLinkUp(self.iface)

    def linkThreadMain(self):
        self.iface_status = isLinkUp(self.iface)
        while not self.finished:
            time.sleep(2)
            status = isLinkUp(self.iface)
            if status != self.iface_status:
                self.packet.set_link(status)
            self.iface_status = status

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
                break # no need to check in other streams

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
        self.txStateAck = dict()
        self.stream_pkts = dict()
        self.txThread = threading.Thread(target=self.txThreadMain, args=())
        self.txThread.daemon = True
        self.txThread.start()

    def set_stream_enable2(self, handle, value, duration, msg):
        requested_stream = None
        for stream_id, stream in self.port.streams.items():
            if not handle:
                stream.enable2 = value
                if value: self.stream_pkts[stream_id] = 0
                self.logger.debug("{}-all: {} {} PKTS: {}".format(
                    msg, self.iface, stream_id, self.stream_pkts[stream_id]))
            elif stream_id == handle:
                requested_stream = stream
                stream.enable2 = value
                if value: self.stream_pkts[stream_id] = 0
                self.logger.debug("{}: {} {} PKTS: {}".format(
                    msg, self.iface, stream_id, self.stream_pkts[stream_id]))
            if duration > 0:
                stream.kws["duration2"] = duration
            else:
                stream.kws.pop("duration2", 0)
        return requested_stream

    def stop_ack_wait(self, handle):
        if handle in self.txStateAck:
            self.txStateAck[handle].set()

    def start_ack_wait(self, handle, wait=0):
        if handle not in self.txStateAck:
            self.txStateAck[handle] = threading.Event()
            self.txStateAck[handle].clear()
        elif wait <= 0:
            self.txStateAck[handle].clear()

        if wait:
            self.txStateAck[handle].wait(wait)

    def startTransmit(self, **kws):
        self.logger.debug("start-tx: {} {}".format(self.iface, kws))

        # enable selected streams
        handle = kws.get('handle', None)
        duration = self.utils.intval(kws, 'duration', 0)
        self.set_stream_enable2(handle, True, duration, "tx-enable")

        # signal the start
        self.logger.debug("signal-tx: {} {}".format(self.iface, kws))
        self.start_ack_wait(handle, 0)

        threading.Timer(1.0, self.txState.set).start()
        #self.txState.set()

    def startTransmitComplete(self, **kws):

        # wait for first packet to be sent
        handle = kws.get('handle', None)
        self.logger.debug("start-tx-ack-0: {} {}".format(self.iface, kws))
        self.start_ack_wait(handle, 10)
        self.logger.debug("start-tx-ack-1: {} {}".format(self.iface, kws))

        # check if all streams are non-contineous
        duration = self.utils.intval(kws, 'duration', 0)
        non_continuous = False
        for stream in self.port.streams.values():
            if stream.kws.get("transmit_mode", "continuous") != "continuous":
                non_continuous = True

        if non_continuous:
            # wait for max 30 seconds to finish ????
            for _ in range(30):
                time.sleep(1)
                if not self.txState.is_set():
                    self.logger.debug("TX Completed waiting 3 sec for RX")
                    time.sleep(3)
                    break
        elif duration > 0:
            self.logger.debug("waiting for duration: {}".format(duration))
            time.sleep(duration)
            self.set_stream_enable2(handle, False, duration, "tx-disable")
            if not handle: self.txState.clear()
        else:
            self.logger.debug("waiting 3 sec")
            time.sleep(3)

        self.logger.debug("start-tx-finished: {} {}".format(self.iface, kws))

    def stopTransmit(self, **kws):

        # disable selected streams
        handle = kws.get('handle', None)
        if handle:
            for stream_id, stream in self.port.streams.items():
                if stream_id == handle:
                    stream.enable2 = False
            return

        if not self.txState.is_set():
            return
        self.logger.debug("stop-tx: {}".format(self.iface))
        self.txState.clear()
        for _ in range(10):
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

    def txThreadMainInnerStart(self, pwa_list, sids):
        if self.dbg > 2:
            self.logger.debug("txThreadMainInnerStart {} {}".format(self.iface, sids.keys()))
        try:
            for stream in self.port.streams.values():
                if stream.stream_id in sids:
                    continue
                if self.dbg > 2:
                    self.logger.debug(" start {} {}/{}".format(stream.stream_id, stream.enable, stream.enable2))
                if stream.enable and stream.enable2:
                    pwa = self.packet.build_first(stream)
                    pwa.tx_time = time.clock()
                    pwa_list.append(pwa)
                    sids[stream.stream_id] = 0
                    self.stop_ack_wait(stream.stream_id)
        except Exception as exp:
            self.logger.log_exception(exp, traceback.format_exc())

        return bool(pwa_list)

    def txThreadMainInner(self):

        sids = {}
        pwa_list = []
        self.logger.debug("txThreadMainInner {} start {}".format(self.iface, self.port.streams.keys()))
        if not self.txThreadMainInnerStart(pwa_list, sids):
            self.logger.debug("txThreadMainInner {} Nothing Todo".format(self.iface))
            return

        tx_count = 0
        while (self.txState.is_set()):
            # call start again to see if new streams are created
            # while there are transmitting streams
            if not self.txThreadMainInnerStart(pwa_list, sids):
                break

            # sort based on next packet send time
            pwa_list.sort(key=self.pwa_sort)

            pwa_next_list = []
            for pwa in pwa_list:
                if not pwa.stream.enable or not pwa.stream.enable2:
                    continue
                self.pwa_wait(pwa)
                try:
                    send_start_time = time.clock()
                    pkt = self.send_packet(pwa, pwa.stream.stream_id)
                    bytesSent = len(pkt)
                    send_time = time.clock() - send_start_time

                    # increment port counters
                    framesSent = self.port.incrStat('framesSent')
                    self.port.incrStat('bytesSent', bytesSent)
                    if self.dbg > 2:
                        self.logger.debug("{} framesSent: {}".format(self.iface, framesSent))
                    pwa.stream.incrStat('framesSent')
                    pwa.stream.incrStat('bytesSent', bytesSent)
                    tx_count = tx_count + 1

                    # increment stream counters
                    stream_tx = self.stream_pkts[pwa.stream.stream_id] + 1
                    self.stream_pkts[pwa.stream.stream_id] = stream_tx
                    if self.dbg > 2 or (self.dbg > 1 and stream_tx%100 == 99):
                        self.logger.debug("{}/{} framesSent: {}".format(self.iface,
                                            pwa.stream.stream_id, stream_tx))
                except Exception as e:
                    self.logger.log_exception(e, traceback.format_exc())
                    pwa.stream.enable2 = False
                else:
                    build_start_time = time.clock()
                    pwa = self.packet.build_next(pwa)
                    if not pwa: continue
                    build_time = time.clock() - build_start_time
                    ipg = self.packet.build_ipg(pwa)
                    pwa.tx_time = time.clock() + ipg - build_time - send_time
                    pwa_next_list.append(pwa)
            pwa_list = pwa_next_list
        self.logger.debug("txThreadMainInner {} Completed {}".format(self.iface, tx_count))

    def pwa_sort(self, pwa):
        return pwa.tx_time

    def pwa_wait(self, pwa):
        delay = pwa.tx_time - time.clock()
        if self.dbg > 2 or (self.dbg > 1 and pwa.left != 0):
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

    def send_packet(self, pwa, stream_name):
        return self.packet.send_packet(pwa, self.iface, stream_name, pwa.left)

    def createInterface(self, intf):
        return self.packet.if_create(intf)

    def deleteInterface(self, intf):
        return self.packet.if_delete(intf)

    def ping(self, intf, ping_dst, index=0):
        return self.packet.ping(intf, ping_dst, index)

    def send_arp(self, intf, index=0):
        return self.packet.send_arp(intf, index)

    def apply_bgp(self, op, enable, intf):
        return self.packet.apply_bgp(op, enable, intf)

    def apply_bgp_route(self, enable, route):
        return self.packet.apply_bgp_route(enable, route)

    def config_igmp(self, mode, intf, host):
        return self.packet.config_igmp(mode, intf, host)


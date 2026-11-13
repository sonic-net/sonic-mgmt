#!/usr/bin/env python

"""
Script to generate PFC storm.

"""
import sys
import optparse
import logging
import logging.handlers
import re
import signal
import subprocess
import time


logger = logging.getLogger('MyLogger')
logger.setLevel(logging.DEBUG)

PFC_TX_ENABLE_TIMEOUT_S = 30


class SignalCleanup():
    def __init__(self, fanoutPfcStorm, endMsg):
        self.fanoutPfcStorm = fanoutPfcStorm
        self.endMsg = endMsg
        signal.signal(signal.SIGTERM, self.sigHandler)

    def sigHandler(self, *args):
        # `sudo pkill -f` delivers a second SIGTERM (relayed by the sudo parent)
        # while this one is still clearing; re-entering would sys.exit() out of
        # the cleanup and leave the port asserting PFC.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        self.fanoutPfcStorm.endAllPfcStorm()

        logger.debug(self.endMsg)
        sys.exit(0)


class FanoutPfcStorm():
    '''
    For eos this class expects all interfaces to be in the front panel interface format
    ex. Ethernet1/1 and not et1_1
    For sonic, the interfaces are the default format
    '''
    def __init__(self, priority, chipName, os):
        self.intfsEnabled = []
        self.priority = priority
        self.switchChip = chipName
        self.os = os
        if os == 'sonic':
            self.intfToMmuPort, self.intfToPort = self._parseInterfaceMapFullSonic()
        else:
            self.intfToMmuPort, self.intfToPort = self._parseInterfaceMapFull()

    def _shellCmd(self, cmd):
        output = ""
        result = subprocess.run([f"{cmd}"], capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            output = result.stdout
        return output

    def _cliCmd(self, cmd):
        output = ""
        if self.os == 'sonic':
            result = subprocess.run([f"bcmcmd '{cmd}'"], capture_output=True, text=True, shell=True)
        else:
            result = subprocess.run(
                ["Cli", "-c", f"{cmd}"], capture_output=True, text=True)
        if result.returncode == 0:
            output = result.stdout
        return output

    def _bcmltshellCmd(self, cmd):
        if self.os == 'sonic':
            return self._cliCmd(f"bsh -c \"{cmd}\"")
        else:
            return self._cliCmd(f"en\nplatform trident shell\nbcmltshell\n{cmd}")

    def _bcmshellCmd(self, cmd):
        return self._cliCmd(f"en\nplatform trident shell\n{cmd}")

    def _parseInterfaceMapFull(self):
        intfToMmuPort = {}
        intfToPort = {}

        output = self._cliCmd("en\nshow platform trident interface map full")

        for line in output.splitlines():
            mo = re.search(
                 r'Intf:\s+(?P<intf>Ethernet[^\s]+)\s+Port:\s+(?P<port>[^\s]+)\s+.*?P2M\[\s*\d+\s*\]:\s+(?P<mmu>\d+)\b',
                 line
            )
            if mo is None:
                continue
            intfToMmuPort[mo.group('intf')] = mo.group('mmu')
            intfToPort[mo.group('intf')] = mo.group('port')

        return intfToMmuPort, intfToPort

    def _parseInterfaceMapFullSonic(self):
        intfToMmuPort = {}
        intfTolPort = {}
        lPortToIntf = {}

        if self.switchChip.startswith(("Tomahawk6", "Tomahawk5", "Tomahawk4")):
            output = self._bcmltshellCmd('knet netif info')
            for info in output.split("Network interface Info:"):
                mo = re.search(r"Name: (?P<intf>Ethernet\d+)[\s\S]{1,100}Port: (?P<lport>\d+)", info)
                if mo is None:
                    continue
                lPortToIntf[mo.group('lport')] = mo.group('intf')
                intfTolPort[mo.group('intf')] = mo.group('lport')
            output = self._cliCmd("show portmap")
            for line in output.splitlines():
                entries = line.split()
                if len(entries) == 7:
                    lport = entries[2]
                    mmuPort = entries[4]
                    if lport in lPortToIntf:
                        intfToMmuPort[lPortToIntf[lport]] = mmuPort
                    intfTolPort[mo.group('intf')] = mo.group('lport')
        else:
            output = self._cliCmd('knet netif show')
            for info in output.split("Interface ID"):
                mo = re.search(r"name=(?P<intf>Ethernet\d+)[\s\S]{1,100}port=(?P<lport>\S+)", info)
                if mo is None:
                    continue
                lPortToIntf[mo.group('lport')] = mo.group('intf')
                intfTolPort[mo.group('intf')] = mo.group('lport')
            output = self._cliCmd("show portmap")
            for line in output.splitlines():
                entries = line.split()
                if len(entries) == 9:
                    lport = entries[0]
                    mmuPort = entries[4]
                    if lport in lPortToIntf:
                        intfToMmuPort[lPortToIntf[lport]] = mmuPort
                    intfTolPort[mo.group('intf')] = mo.group('lport')

        return intfToMmuPort, intfTolPort

    def _clearPfcBackpressure(self, intf):
        '''
        Drop the ASIC PFC assertion for one interface.

        This alone stops the storm; _restorePfcConfig() afterwards is bookkeeping.
        '''
        mmuPort = self.intfToMmuPort[intf]
        port = self.intfToPort[intf]
        if self.switchChip.startswith(("Tomahawk6", "Tomahawk5", "Tomahawk4")):
            self._bcmltshellCmd(f"pt MMU_INTFO_XPORT_BKP_HW_UPDATE_DISr set BCMLT_PT_PORT={mmuPort} PAUSE_PFC_BKP=0")
            self._bcmltshellCmd(f"pt MMU_INTFO_TO_XPORT_BKPr set BCMLT_PT_PORT={mmuPort} PAUSE_PFC_BKP=0")
        else:
            self._bcmshellCmd(f"setreg CHFC2PFC_STATE.{port} PRI_BKP=0")

    def _restorePfcConfig(self, intf):
        '''
        Undo the PFC config startPfcStorm() applied to one interface.
        '''
        if self.os == 'sonic':
            for prio in range(8):
                if (1 << prio) & self.priority:
                    self._shellCmd(f"config interface pfc priority {intf} {prio} off")
            self._shellCmd(f"redis-cli -n 4 DEL \"PORT_QOS_MAP|{intf}\"")
        else:
            self._cliCmd(f"en\nconf\n\nint {intf}\nno priority-flow-control on")
            for prio in range(8):
                if (1 << prio) & self.priority:
                    self._cliCmd(f"en\nconf\n\nint {intf}\nno priority-flow-control priority {prio} no-drop")

    def _pfcTxEnabled(self, intf):
        '''
        Return True or False for PC_PFC ENABLE_TX on the port, or None if the read failed.
        '''
        port = self.intfToPort[intf]
        match = re.search(r'\bENABLE_TX=([01])\b', self._bcmltshellCmd(f"lt PC_PFC lookup PORT_ID={port}"))
        return match.group(1) == '1' if match else None

    def _waitPfcTx(self, intf, enabled, deadline):
        '''
        Wait until orchagent has set PFC transmit on the port in the ASIC to the given state.

        Backpressure asserted while PFC transmit is off sends nothing, and keeps
        sending nothing after transmit is enabled, so it must be asserted after.
        '''
        while self._pfcTxEnabled(intf) != enabled:
            if time.time() > deadline:
                state = "enabled" if enabled else "disabled"
                raise RuntimeError(
                    f"PFC transmit not {state} on {intf} within the {PFC_TX_ENABLE_TIMEOUT_S}s "
                    "shared by the waits for transmit off and on")
            time.sleep(0.2)

    def startPfcStorm(self, intfs):
        '''
        Configure PFC on every interface before asserting backpressure on any,
        so the waits for PFC transmit overlap across interfaces.

        The waits share one PFC_TX_ENABLE_TIMEOUT_S, which a caller's wait after
        start_storm() must allow for (see test_pfcwd_stat_history). The priority-on
        commands between the waits do not count against it, because their time grows
        with the number of interfaces.
        '''
        xgsSonic = self.os == 'sonic' and self.switchChip.startswith(("Tomahawk6", "Tomahawk5", "Tomahawk4"))
        intfs = [intf for intf in dict.fromkeys(intfs) if intf not in self.intfsEnabled]
        txWasEnabled = []
        for intf in intfs:
            # Backpressure lives in the ASIC, so a generator that died without
            # running its cleanup left this interface asserting PFC. Starting from
            # that state emits nothing new and the watchdog never sees a storm
            # begin, so drop it before asserting our own.
            self._clearPfcBackpressure(intf)
            self.intfsEnabled.append(intf)

            if self.os == 'sonic':
                if xgsSonic:
                    oldPfcEnable = self._shellCmd(f"redis-cli -n 4 HGET \"PORT_QOS_MAP|{intf}\" \"pfc_enable\"")
                    if oldPfcEnable.strip() and self._pfcTxEnabled(intf) is not False:
                        txWasEnabled.append(intf)
                self._shellCmd(f"redis-cli -n 4 HSET \"PORT_QOS_MAP|{intf}\" \"pfc_enable\" \"\"")
            else:
                self._cliCmd(f"en\nconf\n\nint {intf}\npriority-flow-control on")
                for prio in range(8):
                    if (1 << prio) & self.priority:
                        self._cliCmd(f"en\nconf\n\nint {intf}\npriority-flow-control priority {prio} no-drop")

        # Otherwise the wait for transmit to come on could see the old ENABLE_TX=1
        # before the clear above reaches the ASIC and turns transmit off.
        waitStart = time.time()
        for intf in txWasEnabled:
            self._waitPfcTx(intf, False, waitStart + PFC_TX_ENABLE_TIMEOUT_S)
        waitLeft = PFC_TX_ENABLE_TIMEOUT_S - (time.time() - waitStart)

        if self.os == 'sonic':
            for intf in intfs:
                for prio in range(8):
                    if (1 << prio) & self.priority:
                        self._shellCmd(f"config interface pfc priority {intf} {prio} on")

        deadline = time.time() + waitLeft
        for intf in intfs:
            mmuPort = self.intfToMmuPort[intf]
            port = self.intfToPort[intf]
            if self.switchChip.startswith(("Tomahawk6", "Tomahawk5", "Tomahawk4")):
                if self.os == 'sonic':
                    self._waitPfcTx(intf, True, deadline)
                self._bcmltshellCmd(
                    f"pt MMU_INTFO_XPORT_BKP_HW_UPDATE_DISr set BCMLT_PT_PORT={mmuPort} PAUSE_PFC_BKP=1")
                self._bcmltshellCmd(
                    f"pt MMU_INTFO_TO_XPORT_BKPr set BCMLT_PT_PORT={mmuPort} PAUSE_PFC_BKP={self.priority}")
            else:
                self._bcmshellCmd(f"setreg CHFC2PFC_STATE.{port} PRI_BKP={self.priority}")

    def endAllPfcStorm(self):
        '''
        Stop the storm on every interface. Idempotent.

        Backpressure is dropped everywhere first, then the config is restored, rather
        than doing both per interface. The list is emptied only once both are done,
        so a cleanup cut short is still retried by main()'s finally.
        '''
        for intf in list(self.intfsEnabled):
            self._clearPfcBackpressure(intf)
        for intf in list(self.intfsEnabled):
            self._restorePfcConfig(intf)
        self.intfsEnabled = []


def main():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-i", "--interface", type="string", dest="interface",
                      help="Interface list to send packets, separated by ','", metavar="Interface")
    parser.add_option('-p', "--priority", type="int", dest="priority",
                      help="PFC class enable bitmap.", metavar="Priority", default=-1)
    parser.add_option("-r", "--rsyslog-server", type="string", dest="rsyslog_server",
                      default="127.0.0.1", help="Rsyslog server IPv4 address", metavar="IPAddress")
    parser.add_option("-c", "--chipName", type="string", dest="chipName", metavar="ChipName",
                      help="Name of chip in the switch, i.e. Tomahawk5")
    parser.add_option("-o", "--os", type="string", dest="os",
                      help="Operating system (eos or sonic)", default="eos")

    (options, args) = parser.parse_args()

    if options.interface is None:
        print("Need to specify the interface to send PFC pause frame packets.")
        parser.print_help()
        sys.exit(1)

    if options.chipName is None:
        print("Need to specify the ChipName to determine what cli to generate PFC pause frame packets.")
        parser.print_help()
        sys.exit(1)

    if options.priority > 255 or options.priority < 0:
        print("Enable class bitmap is not valid. Need to be in range 0-255.")
        parser.print_help()
        sys.exit(1)

    # Configure logging
    handler = logging.handlers.SysLogHandler(address=(options.rsyslog_server, 514))
    handler.ident = 'pfc_gen: '
    logger.addHandler(handler)

    # List of front panel kernel intfs
    interfaces = options.interface.split(',')

    fs = FanoutPfcStorm(options.priority, options.chipName, options.os)
    SignalCleanup(fs, 'PFC_STORM_END')

    logger.debug('PFC_STORM_DEBUG')
    try:
        if options.os == 'eos':
            interfaces = [frontPanelIntfFromKernelIntfName(intf) for intf in interfaces]
        fs.startPfcStorm(interfaces)
        logger.debug('PFC_STORM_START')

        # wait forever until stop
        while True:
            time.sleep(100)
    except Exception as e:
        logger.error(f'PFC_STORM_ERROR {e}')
        raise
    finally:
        # An interface missing from the portmap raises part way through the
        # loop; without this the ones already started stay asserted.
        fs.endAllPfcStorm()


def frontPanelIntfFromKernelIntfName(intf):
    return intf.replace("et", "Ethernet").replace("_", "/")


if __name__ == "__main__":
    main()

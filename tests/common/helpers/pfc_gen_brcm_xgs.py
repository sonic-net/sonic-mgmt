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


class SignalCleanup():
    def __init__(self, fanoutPfcStorm, endMsg):
        self.fanoutPfcStorm = fanoutPfcStorm
        self.endMsg = endMsg
        signal.signal(signal.SIGTERM, self.sigHandler)

    def sigHandler(self, *args):
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

        if self.switchChip.startswith(("Tomahawk5", "Tomahawk4")):
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

    def _endPfcStorm(self, intf):
        '''
        Intf format is Ethernet1/1

        The users of this class are only expected to call
        startPfcStorm and endAllPfcStorm
        '''
        mmuPort = self.intfToMmuPort[intf]
        port = self.intfToPort[intf]
        if self.switchChip.startswith(("Tomahawk5", "Tomahawk4")):
            self._bcmltshellCmd(f"pt MMU_INTFO_XPORT_BKP_HW_UPDATE_DISr set BCMLT_PT_PORT={mmuPort} PAUSE_PFC_BKP=0")
            self._bcmltshellCmd(f"pt MMU_INTFO_TO_XPORT_BKPr set BCMLT_PT_PORT={mmuPort} PAUSE_PFC_BKP=0")
        else:
            self._bcmshellCmd(f"setreg CHFC2PFC_STATE.{port} PRI_BKP=0")
        if self.os == 'sonic':
            for prio in range(8):
                self._shellCmd(f"config interface pfc priority {intf} {prio} off")
            self._shellCmd(f"redis-cli -n 4 DEL \"PORT_QOS_MAP|{intf}\"")
        else:
            self._cliCmd(f"en\nconf\n\nint {intf}\nno priority-flow-control on")
            for prio in range(8):
                self._cliCmd(f"en\nconf\n\nint {intf}\nno priority-flow-control priority {prio} no-drop")

    def startPfcStorm(self, intf):
        if intf in self.intfsEnabled:
            return
        self.intfsEnabled.append(intf)

        mmuPort = self.intfToMmuPort[intf]
        port = self.intfToPort[intf]
        if self.os == 'sonic':
            self._shellCmd(f"redis-cli -n 4 HSET \"PORT_QOS_MAP|{intf}\" \"pfc_enable\" \"\"")
            for prio in range(8):
                if (1 << prio) & self.priority:
                    self._shellCmd(f"config interface pfc priority {intf} {prio} on")
        else:
            self._cliCmd(f"en\nconf\n\nint {intf}\npriority-flow-control on")
            for prio in range(8):
                if (1 << prio) & self.priority:
                    self._cliCmd(f"en\nconf\n\nint {intf}\npriority-flow-control priority {prio} no-drop")

        if self.switchChip.startswith(("Tomahawk5", "Tomahawk4")):
            self._bcmltshellCmd(f"pt MMU_INTFO_XPORT_BKP_HW_UPDATE_DISr set BCMLT_PT_PORT={mmuPort} PAUSE_PFC_BKP=1")
            self._bcmltshellCmd(f"pt MMU_INTFO_TO_XPORT_BKPr set BCMLT_PT_PORT={mmuPort} PAUSE_PFC_BKP={self.priority}")
        else:
            self._bcmshellCmd(f"setreg CHFC2PFC_STATE.{port} PRI_BKP={self.priority}")

    def endAllPfcStorm(self):
        for intf in self.intfsEnabled:
            self._endPfcStorm(intf)


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
    for intf in interfaces:
        if options.os == 'eos':
            intf = frontPanelIntfFromKernelIntfName(intf)
        fs.startPfcStorm(intf)
    logger.debug('PFC_STORM_START')

    # wait forever until stop
    while True:
        time.sleep(100)


def frontPanelIntfFromKernelIntfName(intf):
    return intf.replace("et", "Ethernet").replace("_", "/")


if __name__ == "__main__":
    main()

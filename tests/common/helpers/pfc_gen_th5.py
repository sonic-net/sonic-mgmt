#!/usr/bin/env python

"""
Script to generate PFC storm.

"""
import binascii
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
    Expects all interfaces to be in the front panel interface format
    ex. Ethernet1/1 and not et1_1
    '''
    def __init__(self, priority):
        self.intfToMmuPort = self._parseInterfaceMapFull()
        self.intfsEnabled = []
        self.priority = priority

    def _cliCmd(self, cmd):
        output = ""
        result = subprocess.run(
            ["Cli", "-c", f"{cmd}"], capture_output=True, text=True)
        if result.returncode == 0:
            output = result.stdout
        return output

    def _bcmltshellCmd(self, cmd):
        return self._cliCmd(f"en\nplatform trident shell\nbcmltshell\n{cmd}") 

    def _parseInterfaceMapFull(self):
        intfToMmuPort = {}

        output = self._cliCmd(f"en\nshow platform trident interface map full")

        for line in output.splitlines():
            mo = re.search('Intf: (?P<intf>Ethernet\S+).{1,100}P2M\[ {0,3}\d+\]: {1,3}(?P<mmu>\S+)', line)
            if mo is None:
                continue
            intfToMmuPort[mo.group('intf')] = mo.group('mmu')

        return intfToMmuPort

    def _endPfcStorm(self, intf):
        '''
        Intf format is Ethernet1/1

        The users of this class are only expected to call
        startPfcStorm and endAllPfcStorm
        '''
        mmuPort = self.intfToMmuPort[intf]
        self._bcmltshellCmd(f"pt MMU_INTFO_XPORT_BKP_HW_UPDATE_DISr set BCMLT_PT_PORT={mmuPort} PAUSE_PFC_BKP=0")
        self._bcmltshellCmd(f"pt MMU_INTFO_TO_XPORT_BKPr set BCMLT_PT_PORT={mmuPort} PAUSE_PFC_BKP=0")
        self._cliCmd(f"en\nconf\n\nint {intf}\nno priority-flow-control on")
        for prio in range(8):
            self._cliCmd(f"en\nconf\n\nint {intf}\nno priority-flow-control priority {prio} no-drop")

    def startPfcStorm(self, intf):
        if intf in self.intfsEnabled:
            return
        self.intfsEnabled.append(intf)

        mmuPort = self.intfToMmuPort[intf]
        self._cliCmd(f"en\nconf\n\nint {intf}\npriority-flow-control on")
        for prio in range(8):
            if (1 << prio) & self.priority:
                self._cliCmd(f"en\nconf\n\nint {intf}\npriority-flow-control priority {prio} no-drop")
        self._bcmltshellCmd(f"pt MMU_INTFO_XPORT_BKP_HW_UPDATE_DISr set BCMLT_PT_PORT={mmuPort} PAUSE_PFC_BKP=1")
        self._bcmltshellCmd(f"pt MMU_INTFO_TO_XPORT_BKPr set BCMLT_PT_PORT={mmuPort} PAUSE_PFC_BKP=0xff")


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

    (options, args) = parser.parse_args()

    if options.interface is None:
        print("Need to specify the interface to send PFC pause frame packets.")
        parser.print_help()
        sys.exit(1)

    if options.priority > 255 or options.priority < 0:
        print("Enable class bitmap is not valid. Need to be in range 0-255.")
        parser.print_help()
        sys.exit(1)

    # Configure logging
    handler = logging.handlers.SysLogHandler(address=(options.rsyslog_server, 514))
    logger.addHandler(handler)

    # List of front panel kernel intfs
    interfaces = options.interface.split(',')

    fs = FanoutPfcStorm(options.priority)
    fsCleanup = SignalCleanup(fs, 'PFC_STORM_END')

    logger.debug('PFC_STORM_DEBUG')
    for intf in interfaces:
       fs.startPfcStorm( frontPanelIntfFromKernelIntfName(intf))
    logger.debug('PFC_STORM_START')

    # wait forever until stop
    while True:
       time.sleep(100)

def frontPanelIntfFromKernelIntfName(intf):
   return intf.replace("et", "Ethernet").replace("_", "/")


if __name__ == "__main__":
    main()

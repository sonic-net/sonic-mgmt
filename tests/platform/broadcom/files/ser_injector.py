#!/usr/bin/env python

import subprocess
import re
import time
from collections import defaultdict

# Global parameter for memory scanners
MEMORY_SCAN_INTERVAL_USEC = int(3e5)
MEMORY_SCAN_ENTRIES = 16384
SRAM_SCAN_INTERVAL_USEC = int(3e5)
SRAM_SCAN_ENTRIES = 16384

DEFAULT_SER_TEST_TIME_SEC = 1200

DEFAULT_SER_INJECTION_INTERVAL_SEC = 5
DEFAULT_SYSLOG_POLLING_INTERVAL_SEC = 0.1

# The following memory tables do not get corrected when a ser is injected into them! Let's take them out for now
# until the underlying reason is answered by Broadcom
UNTESTABLE_MEMORY_TABLES = [u'L3_ENTRY_IPV6_MULTICAST.ipipe0', u'L3_DEFIP_ALPM_IPV6_64.ipipe0', u'EGR_IP_TUNNEL_MPLS.epipe0',
                            u'MODPORT_MAP_MIRROR.ipipe0', u'L3_DEFIP_ALPM_IPV6_128.ipipe0', u'L3_ENTRY_IPV4_MULTICAST.ipipe0',
                            u'L3_ENTRY_IPV6_UNICAST.ipipe0', u'L3_DEFIP_ALPM_IPV4.ipipe0', u'FP_GLOBAL_MASK_TCAM.ipipe0',
                            u'FP_STORM_CONTROL_METERS.ipipe0', u'FP_GM_FIELDS.ipipe0']

# Not every memory table orrection is detected by the test case. This could be due to the
# losses over syslog transport. Make the test iterate over different memory tables in order to cover
# every memory table
DEFAULT_TEST_ITERATION = 3

def run_cmd(cmd):
    '''
    @summary: Utility that runs a command in a subprocess
    @param cmd: Command to be run
    @return: stdout of the command run
    @return: stderr of the command run
    '''
    out = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, stderr = out.communicate()
    return stdout, stderr

class BcmMemory():
    '''
    @summary: BcmMemory captures different memory tables of the Broadcom ASIC. Memory are split into two categories:
              cached and uncached. Broadcom SER correction is enabled for cached memory tables. For cached memory tables,
              memory attributes are also retreived
    '''
    def __init__(self):
        '''
        @summary: Class constructor
        '''
        self.cached_memory = {}
        self.uncached_memory = {}
        self.memory_address = {}

    def get_memory_attributes(self, mem):
        '''
        @summary: Reads Broadcom memory attributes using list command. Attributes include start address, flags, 
                  number of entries, entry size in bytes and entry size in words. The method uses regex to parse
                  the command output since there is not SAI APIs for it.
        '''
        stdout, stderr = run_cmd(["bcmcmd",  "list " + mem])

        attributes = stdout.decode("utf-8").split("\n")

        attr = {}
        m = re.search('^Memory:.*address (.+)$', attributes[1])
        attr['address'] = int(m.group(1), 16)

        m = re.search('^Flags: (.*)$', attributes[2])
        attr['flags'] = m.group(1).strip().split(" ")

        m = re.search('^Entries: (\d+).*each (\d+) bytes (\d+) words', attributes[4])
        attr['entries'] = int(m.group(1))
        attr['size_byte'] = int(m.group(2))
        attr['size_word'] = int(m.group(3))

        return attr

    def read_memory(self):
        '''
        @summary: Read different memory tables using cache command. It update both cached_memory and uncached_memory
                  hash tables. For cached memory, ut aksi creat a reverse index of address to memory table name. This indez
                  is stored in memory_address hash table

                  Sample output of bcmcmd 'cache' command:
                  cache
                  Caching is off for:
                       COS_MAP_SEL.ipipe0
                       CPU_COS_MAP_DATA_ONLY.ipipe0
                       .
                  Caching is on for:
                       ALTERNATE_EMIRROR_BITMAP.ipipe0
                       BCAST_BLOCK_MASK.ipipe0
        '''
        stdout, stderr = run_cmd(['bcmcmd', 'cache'])

        cache_flag = False
        memories = stdout.decode("utf-8").split("\n")

        # remove Head line and 3 trailing prompt lines 
        memories = memories[1 : len(memories) - 3]
        for memory in memories:
            if memory.find("Caching is off") > -1:
                cache_flag = False
            elif memory.find("Caching is on") > -1:
                cache_flag = True
            else:
                if cache_flag:
                    self.cached_memory.update({mem:{} for mem in memory.strip().split(" ")})
                else:
                    self.uncached_memory.update({mem:{} for mem in memory.strip().split(" ")})

        self.memory_address = defaultdict(list)
        for mem in self.cached_memory:
            self.cached_memory[mem] = self.get_memory_attributes(mem)
            self.memory_address[self.cached_memory[mem]['address']].append(mem)

    def get_cached_memory(self):
        '''
        @summary: Accessor method for cached_memory hash table
        '''
        return self.cached_memory

    def get_memory_by_address(self):
        '''
        @summary: Accessor method for memory_address hash table
        '''
        return self.memory_address

class SerTest(object):
    '''
    @summary: SerTest conducts SER injection test on Broadcom ASIC. SER injection test use Broadcom SER injection
              utility to insert SER into different memory tables. Before the SER injection, Broadcom mem/sram scanners 
              are started and syslog file location is marked. Subsequently, the test proceeeds into monitoring syslog
              for any SER correction taking place.
    '''
    def __init__(self, test_time_sec = DEFAULT_SER_TEST_TIME_SEC, 
                 ser_injection_interval_sec = DEFAULT_SER_INJECTION_INTERVAL_SEC,
                 syslog_poll_interval_sec = DEFAULT_SYSLOG_POLLING_INTERVAL_SEC,
                 test_iteration = DEFAULT_TEST_ITERATION):
        '''
        @summary: Class constructor
        '''
        self.syslog_poll_interval_sec = syslog_poll_interval_sec
        self.test_time_sec = test_time_sec
        self.ser_injection_interval_sec = ser_injection_interval_sec
        self.test_iteration = test_iteration
        self.mem_verification_pending = []
        self.mem_verified = {}
        self.mem_failed = {}
        self.mem_ser_unsupported = []
        self.bcmMemory = BcmMemory()

    def test_memory(self):
        '''
        @summary: perform SER memory test
        '''
        global MEMORY_SCAN_INTERVAL_USEC
        global MEMORY_SCAN_ENTRIES
        global SRAM_SCAN_INTERVAL_USEC
        global SRAM_SCAN_ENTRIES
        global UNTESTABLE_MEMORY_TABLES

        self.bcmMemory.read_memory()
        self.mem_verification_pending = list(set(self.bcmMemory.get_cached_memory().keys()) - set(UNTESTABLE_MEMORY_TABLES))

        # Enable memory scan and sram scan once for all memories
        self.enable_mem_scan(MEMORY_SCAN_INTERVAL_USEC, MEMORY_SCAN_ENTRIES)
        self.enable_sram_scan(SRAM_SCAN_INTERVAL_USEC, SRAM_SCAN_ENTRIES)

        count = 0
        while (count < self.test_iteration and len(self.mem_verification_pending) > 0):
            count += 1
            print("Test iteration no. %s" % count)
            test_memory = list(self.mem_verification_pending)
            del self.mem_verification_pending[:]
            self.run_test(test_memory)

        print("SER Test succeeded for memories (%s): %s" % (len(self.mem_verified), self.mem_verified))
        print("SER Test failed for memories (%s): %s" % (len(self.mem_failed), self.mem_failed))
        print("SER Test timed out for memories (%s): %s" % (len(self.mem_verification_pending), self.mem_verification_pending))
        print("SER Test is not supported for memories (%s): %s" % (len(self.mem_ser_unsupported), self.mem_ser_unsupported))

    def enable_memory_scan(self, cmd, interval_usec, rate):
        '''
        @summary: Enable Broadcom memory scan
        @param cmd: Broadcom to use
        @param interval_usec: memory scanner interval i usec
        @param rate: rate (number of entries) per interval
        '''
        for x in range(3):
            stdout, stderr = run_cmd(["bcmcmd", cmd + " interval=" + str(interval_usec) + " rate=" + str(rate)])
            lines = stdout.decode("utf-8").split("\n")
            if lines[1].find('mSCAN: Started on unit 0') > -1:
                return

        raise ValueError('Failed to start memory scanner: %s' % cmd) 

    def enable_mem_scan(self, interval_usec, rate):
        '''
        @summary: Wrapper around enable_memory_scan
        @param interval_usec: memory scanner interval i usec
        @param rate: rate (number of entries) per interval
        '''
        self.enable_memory_scan('memscan', interval_usec, rate)

    def enable_sram_scan(self, interval_usec, rate):
        '''
        @summary: Enable Broadcom sram scan
        @param interval_usec: memory scanner interval i usec
        @param rate: rate (number of entries) per interval
        '''
        self.enable_memory_scan('sramscan', interval_usec, rate)

    def verify_ser(self, entry, log):
        '''
        @summary: verify SER log entry
        @param entry: indext of the memory table where SER was injected
        @param log: syslog log line

        @return: memory table name
        @return: Flag if SER injection entry matches log line entry
        '''
        m = re.search("^.*addr:(.*) port.*index: (\d+)", log)

        address = int(m.group(1), 16)
        mem_entry = int(m.group(2))

        memory = self.bcmMemory.get_memory_by_address()
        if address in memory:
            return memory[address], entry == mem_entry

        return None, None

    def inject_ser(self, mem, index = 0):
        '''
        @summary: Inject SER error suing Broadcom ser inject command
        @param mem: name of the memory table to inject SER into
        @param index: index of the entry to inject SER into
        '''
        return run_cmd(["bcmcmd",  "ser inject memory=" + mem + " index=" + str(index)])

    def verify_and_update_test_result(self, entry, line):
        '''
        @summary: Verify log line and update test result
        @param entry: index of the entry to inject SER into
        @param log: syslog log line
        '''
        mem, entry_found = self.verify_ser(entry, line)
        if mem is not None:
            # memory could be aliased, mark all aliased memory as passed/failed
            for m in mem:
                if entry_found:
                    if m in self.mem_verified:
                        self.mem_verified[m] += 1
                    else:
                        print("Successfully tested memory %s" % m)
                        self.mem_verified.update({m : 1})
                else:
                    if m in self.mem_failed:
                        self.mem_failed[m] += 1
                    else:
                        print("Failed verification for memory %s, syslog '%s'" % (m, line))
                        self.mem_failed.update({m : 1})

                if m in self.mem_verification_pending:
                    self.mem_verification_pending.remove(m)
                else:
                    print("Memory %s appeared more than once" % m)
        else:
            print("Memory corresponding to the following syslog was not found! Syslog: '%s'" % line)

    def run_test(self, memory, entry = 0):
        '''
        @summary: Run SER injection test on cached memory tables
        @param memory: Cached memory tables
        @param entry: index of the entry to inject SER into
        '''
        with open('/var/log/syslog') as syslog_file:
            # mark current location of the syslog file
            syslog_file.seek(0, 2)
            for mem in memory:
                stdout, stderr = self.inject_ser(mem)
                if stdout.find('SER correction for it is not currently supported') > -1:
                    print("memory %s does not support ser" % mem)
                    self.mem_ser_unsupported.append(mem)
                else:
                    self.mem_verification_pending.append(mem)
                time.sleep(self.ser_injection_interval_sec)

            count = 0
            while len(self.mem_verification_pending) > 0:
                line = syslog_file.readline()
                if line:
                    if line.find('SER_CORRECTION') > -1:
                        self.verify_and_update_test_result(entry, line)
                else:
                    time.sleep(self.syslog_poll_interval_sec)
                    count += 1
                    if count > self.test_time_sec / self.syslog_poll_interval_sec:
                        print("timed out waiting for ser correction...")
                        break

def main():
    start_time = time.time()
    serTest = SerTest()
    serTest.test_memory()
    print("--- %s seconds ---" % (time.time() - start_time))

if __name__ == "__main__":
    main()

#!/usr/bin/python

from __future__ import print_function
from ansible.module_utils.basic import *
from datetime import datetime

import shelve

DOCUMENTATION = '''
---
module: action_sync
version_added:
author: Praveen Chaudhary (pchaudhary@linkedin.com)

description:
    - this module will store below DB with information about topology,
    dut and server.
    - DB format: {
        current_topo: {
            topo_name: "<topo_topo_name>",
            "deploy-mg": "<True\False>",
            "dut": <dut>,
            "server: <server>
        },
        actions : {
            success: [
                "add-topo <topo_topo_name> <dut> <server>",
                "deploy-mg <topo_topo_name> <dut> <server>",
                "run_test <test-topo_name> <topo_topo_name> <dut> <server>",
            ],
            all: [
                "deploy-mg <topo_topo_name> <dut> <server>",
                "run_test <topo_topo_name> <dut> <server>",
                "run_test <test-topo_name> <topo_topo_name> <dut> <server>",
            ]
        }
    }
    - to start with current_topo will be None, or will not exist, or DB will
    not exist. All 3 will be treated as current_topo == None.

    - if action is add_topo, makes sure current_topo is None. Else fail. Fill
    new information with current_topo['deploy-mg'] is False.

    - if action is deploy-mg, makes sure current_topo['topo_name'] == topo. Match
    dut and server too. Set current_topo['topo_name'] == True.

    - run_test: Make Sure, deploy-mg it True.
    - remove-topo: makes sure current_topo['topo_name'] == topo. Match
    dut and server too. Assign current_topo == None.
    - For each action, store it in either action['success'] or action['all'].

    Note:
    - deploy-mg may not be necessary always after add topo, for that we can add
    avoid deploy-mg parameter later or keep deploy-mg == True in DB.
    - add-topo can be issues on same topo again.
'''

EXAMPLES = '''
 - topo_name: test action sync
    action_sync: action={{ action }} topo={{ topo_name }} dut = {{ dut }}
        server = {{ server }} test_name={{ test_name}}
    connection: local
    register: action_sync
'''

MaxLogLen = 25

class ActionSync(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
              action=dict(required=True, type='str'),
              topo =dict(required=True, type='str'),
              dut=dict(required=True, type='str'),
              server=dict(required=True, type='str'),
              test_name=dict(required=False, type='str'),
            ),
            supports_check_mode=True)

        self.action = self.module.params['action']
        self.topo = self.module.params['topo']
        self.dut = self.module.params['dut']
        self.server = self.module.params['server']
        self.test_name = self.module.params.get('test_name')

        # class variables
        self.file = "actionDb"

        # DB & Results
        self.db = self.readDbFile()

        return

    def run(self):
        """
            Main method of the class

        """
        try :
            # init DB, If Not Created.
            if len(self.db) == 0:
                self.initDB()

            if self.action == "add-topo":
                self.processAddTopo()
            elif self.action == "deploy-mg":
                self.processDeploMg()
            elif self.action == "run-tests":
                self.processRunTests()
            elif self.action == "remove-topo":
                self.processRemoveTopo()
            else:
                raise Exception("Wrong Action:{}".format(self.action))

            self.facts   =  {'action_sync': dict(self.db)}
            self.db.close()
            self.module.exit_json(ansible_facts=self.facts)
        except Exception as e:
            self.facts   =  {'action_sync': dict(self.db)}
            self.db.close()
            self.module.fail_json(msg="{}".format(e), ansible_facts=self.facts)

        return

    def processAddTopo(self):

        d = self.db['current_topo']

        '''
            if None add this topo, or same topo is loaded already.
            Later is needed if add-topo failed at later stages.
        '''
        if d is None or (d['topo_name'] == self.topo and d['dut'] == self.dut and \
            d['server'] == self.server):

            d = dict()
            d['topo_name'] = self.topo
            d['deploy-mg'] = False
            d['dut'] = self.dut
            d['server'] = self.server
            self.db['current_topo'] = d
            self.logSuccess()
        else:
            self.logFailure()
            raise Exception("{} failed".format(self.action))
        return

    def processDeploMg(self):

        d = self.db['current_topo']

        '''
            Deploy Mg if same setup and topo is added.
        '''
        if d is None or d['topo_name'] != self.topo or d['dut'] != self.dut or \
            d['server'] != self.server:

            self.logFailure()
            raise Exception("{} failed".format(self.action))
        else:
            d['deploy-mg'] = True
            self.db['current_topo'] = d
            self.logSuccess()

        return

    def processRemoveTopo(self):

        d = self.db['current_topo']

        '''
            Remove Topo if same setup and topo is added.
        '''
        if d is None or d['topo_name'] != self.topo or d['dut'] != self.dut or \
            d['server'] != self.server:

            self.logFailure()
            raise Exception("{} failed".format(self.action))
        else:
            self.db['current_topo'] = None
            self.logSuccess()

        return

    def processRunTests(self):

        d = self.db['current_topo']

        if self.test_name is None:
            self.logFailure()
            raise Exception("No test_name Provided")

        # if None add this topo
        if d is None or d['topo_name'] != self.topo or d['dut'] != self.dut or \
            d['server'] != self.server:

            self.logFailure()
            raise Exception("{} failed".format(self.action))
        else:
            self.logSuccess()

    def logSuccess(self):

        log = "{}: {} topo={} dut={} server={}".format(datetime.now(), \
            self.action, self.topo, self.dut, self.server)
        if self.action == "run-tests" and self.test_name is not None:
            log = log + " test=" + self.test_name

        d = self.db['actions']

        if len(d['success']) == MaxLogLen:
            d['success'].pop(0)

        d['success'].append(log)
        self.db['actions'] = d

        self.logFailure(logAs='SUCC')
        return

    def logFailure(self, logAs='FAIL'):

        log = "{}: -{}- {} topo={} dut={} server={}".format(datetime.now(), \
            logAs, self.action, self.topo, self.dut, self.server)
        if self.action == "run-tests" and self.test_name is not None:
            log = log + " test=" + self.test_name

        d = self.db['actions']

        if len(d['all']) == 2*MaxLogLen:
            d['all'].pop(0)

        d['all'].append(log)
        self.db['actions'] = d

        return

    def initDB(self):
        self.db['current_topo'] = None
        self.db['actions'] = {
            'success': [],
            'all': []
        }

        return

    def readDbFile(self):
        """
            Function to read shelve DB file
            TODO: Take lock.
        """
        return shelve.open(self.file)

def main():
    actionSync = ActionSync()
    actionSync.run()

    return

if __name__ == "__main__":
    main()

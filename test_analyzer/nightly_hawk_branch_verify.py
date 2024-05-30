#!/bin/env python
'''
branch verification
1: collect all testbeds information
2: determine the testbeds which need to run based on input branch
3: collect images
4: option run the redeploy for these testbeds
5: trigger nightly testbed builds for these testbeds
6: waiting all pipeline builds done
7: collect result
'''

from __future__ import print_function, division

import argparse
import json
import logging
import os
import sys
import requests
import time
import datetime
import yaml
import re

from nightly_hawk_autoRecovery_cfg import curr_convert_to_trusty_images_dict
from nightly_hawk_autoRecovery_cfg import nightly_pipeline_internal
from nightly_hawk_autoRecovery_cfg import nightly_pipeline_master
from nightly_hawk_autoRecovery_cfg import nightly_pipeline_202012
from nightly_hawk_autoRecovery_cfg import nightly_pipeline_202205
from nightly_hawk_autoRecovery_cfg import branch_verify_cfg

from nightly_hawk_common import NightlyPipelineCheck, TbShare

NIGHTLY_HAWK_DIR = os.path.abspath(os.path.dirname(__file__))
SONIC_MGMT_DIR = os.path.dirname(NIGHTLY_HAWK_DIR)
ANSIBLE_DIR = os.path.join(SONIC_MGMT_DIR, 'ansible')
NIGHTLY_PIPELINE_YML_DIR = os.path.join(SONIC_MGMT_DIR, '.azure-pipelines/nightly')


# logging.basicConfig(
#     stream=sys.stdout,
#     level=logging.INFO,
#     format='%(asctime)s %(filename)s:%(name)s:%(lineno)d %(levelname)s - %(message)s')
# logger = logging.getLogger(__name__)

from nightly_hawk_common import logger

import yaml
from yaml.loader import SafeLoader


class Nightly_hawk_branch_verify(object):
    def __init__(self, verbose = False, test_brief='Test-Brief', branch = None, type = None, image = None, imagetag = None, script=None, specific=None, skip=False, lock_timeout=7200, pipeline_timeout=1800):
        self.verbose = verbose
        self.test_brief = test_brief
        self.branch = branch
        self.script_branch = script
        self.testbed_specific = specific
        self.skip_upload_result = skip
        self.image_folder = image
        self.imagetag = imagetag
        self.testbeds = {}
        self.testbeds_inventory = {}  # record hwsku for each testbed and dut
        self.curr_building_testbed_list = []
        self.pipeline_parser_analyzer_dict = {}
        self.case_verify_pipeline_id = 953
        self.lock_timeout = lock_timeout
        self.pipeline_timeout = pipeline_timeout

        self.parse_testbeds_inventory()

        self.nightly_pipeline_check = NightlyPipelineCheck()

        # self.pipeline_parser_analyzer_dict = self.nightly_pipeline_check.collect_nightly_build_pipelines('nightly')
        # with open('pipeline_parser_dict_debug_branch_verify.json') as f:
        # # with open('pipeline_parser_dict_debug.json') as f:
        #     logger.info("parser_pipeline_info using cache file")
        #     self.pipeline_parser_analyzer_dict = json.load(f)

        logger.debug("Get all nightly test pipeline information: {}".format(self.pipeline_parser_analyzer_dict))


    def parse_testbeds_inventory(self):
        self.testbeds_inventory = {}
        dut_to_tb = {}
        with open(os.path.join(SONIC_MGMT_DIR, 'ansible/testbed.yaml')) as fp:
            yml = yaml.load(fp, Loader=SafeLoader)
            for testbed in yml:
                tb = testbed['conf-name']
                self.testbeds_inventory[tb] = {}
                for dut in testbed['dut']:
                    self.testbeds_inventory[tb][dut] = {}
                    dut_to_tb[dut] = tb
        self._parse_dut_inventory(dut_to_tb)


    def _parse_dut_inventory(self, dut_to_tb):
        for inv_filename in ('str', 'str2', 'str3', 'strsvc', 'strsvc2', 'bjw', 'bjw2'):
            with open(os.path.join(SONIC_MGMT_DIR, 'ansible/{}'.format(inv_filename)), "r") as inv:
                yml = yaml.load(inv, Loader=SafeLoader)
                for section in yml.values():
                    if 'vars' in section and 'hosts' in section:
                        for hostname, hostinfo in section['hosts'].items():
                            tb = dut_to_tb.get(hostname, None)
                            if tb and hostname in self.testbeds_inventory[tb]:
                                self.testbeds_inventory[tb][hostname]['hwsku'] = \
                                    hostinfo['hwsku'] if 'hwsku' in hostinfo else section['vars'].get('hwsku', None)
                    elif 'hosts' in section:
                        for hostname, hostinfo in section['hosts'].items():
                            tb = dut_to_tb.get(hostname, None)
                            if tb and hostname in self.testbeds_inventory[tb] and 'hwsku' in hostinfo and 'ansible_host' in hostinfo:
                                self.testbeds_inventory[tb][hostname]['hwsku'] = hostinfo['hwsku']


    def lookup_dut_hwsku(self, testbed):
        if testbed not in self.testbeds_inventory:
            return None
        hwsku = set()
        for dutinfo in self.testbeds_inventory[testbed].values():
            if 'hwsku' in dutinfo and dutinfo['hwsku'] != None:
                hwsku.add(dutinfo['hwsku'])
        if len(hwsku) != 1:
            return None
        else:
            return list(hwsku)[0]


    def check_tb_in_require_bjw_lab(self, testbed):
        if testbed not in self.testbeds_inventory:
            return False
        inv = set()
        for dutname in self.testbeds_inventory[testbed]:
            pre = dutname.split('-', 1)[0]
            if pre != None:
                inv.add(pre)
        if len(inv) != 1:
            return False
        else:
            return list(inv)[0] == 'bjw'


    def check_testbed_is_available(self, testbed):
        logger.debug("check_testbed_is_available {} ".format(testbed))

        testbed_pipeline_info = self.pipeline_parser_analyzer_dict[testbed]
        for branch, branch_pipeline_info in testbed_pipeline_info.items():
            for key, value in branch_pipeline_info.items():
                count, data_list = self.nightly_pipeline_check.get_pipeline_status_result_by_pipeline_id(value['pipeline_id'])
                if count == None or count == 0:
                    continue
                else:
                    # fixme, range(3)
                    for i in range(min(3, count)):
                        if data_list[i]["state"] != "completed":
                            logger.info("testbed {} is not availabe due to pipeline id {} ".format(testbed, value['pipeline_id']))
                            return False
                        
        logger.info("testbed {} is available".format(testbed))
        return True

    def get_testbeds(self, topo):
        branch = self.branch
        testbeds_cfg_branch = branch_verify_cfg[branch]
        if topo == 'all':
            for topo, testbeds_cfg_hwsku in testbeds_cfg_branch.items():
                for hwsku, testbeds in testbeds_cfg_hwsku.items():
                    for testbed in testbeds:
                        logger.info("branch {} topo {} hwskw {} testbed {} ".format(branch, topo, hwsku, testbed))
                        if self.check_testbed_is_available(testbed):
                            logger.info("pipeline_dict {}".format(self.pipeline_parser_analyzer_dict[testbed]))
                            self.testbeds[testbed] = {}
                            break
                        # fixme, how to check the pipeline whether has unfinished job
        else:
            testbeds_cfg_hwsku = branch_verify_cfg[branch][topo]
            for hwsku, testbeds in testbeds_cfg_hwsku.items():
                for testbed in testbeds:
                    logger.info("branch {} topo {} hwskw {} testbed {} ".format(branch, topo, hwsku, testbed))
                    if self.check_testbed_is_available(self.pipeline_parser_analyzer_dict[testbed]):
                        logger.info("pipeline_dict {}".format(self.pipeline_parser_analyzer_dict[testbed]))
                        self.testbeds[testbed] = {}
                        break            

        logger.info("testbeds {}".format(self.testbeds))

    # def parser_library(self, library):
    #     logger.debug("input library {}".format(library))


    #     return library_json

    def collect_testbeds_information(self):
        logger.debug("collect_testbeds_information")
        for testbed in self.testbeds.keys():
            logger.debug("collect_testbeds_information testbed {}".format(testbed))
            pipeline_info = self.pipeline_parser_analyzer_dict[testbed][self.branch]
            for _, pipeline in pipeline_info.items():
                self.testbeds[testbed]['pipeline_id'] = pipeline['pipeline_id']
                self.testbeds[testbed]['image_url'] = pipeline['image_url']
                self.testbeds[testbed]['yml'] = os.path.basename(pipeline['path']) 

                yml = os.path.join(SONIC_MGMT_DIR, pipeline['path'])
                yml_dict = self.nightly_pipeline_check.parser_nightly_pipeline_yml_File(yml)
                testbed_specific = yml_dict.get('TESTBED_SPECIFIC', None)
                nightly_test_timeout = yml_dict.get('NIGHTLY_TEST_TIMEOUT', None)
                skip_test_results_uploading = yml_dict.get('SKIP_TEST_RESULTS_UPLOADING', None)
   
                if testbed_specific == None and 'TESTBED_SPECIFIC' in self.testbeds[testbed]:
                    logger.info("pipeline has no TESTBED_SPECIFIC item, remove {}".format(self.testbeds[testbed]['TESTBED_SPECIFIC']))
                    del self.testbeds[testbed]['TESTBED_SPECIFIC']
                elif self.testbed_specific:
                    self.testbeds[testbed]['TESTBED_SPECIFIC'] = self.testbed_specific

                if nightly_test_timeout == None and 'NIGHTLY_TEST_TIMEOUT' in self.testbeds[testbed]:
                    logger.info("pipeline has no NIGHTLY_TEST_TIMEOUT item, remove {}".format(self.testbeds[testbed]['NIGHTLY_TEST_TIMEOUT']))
                    del self.testbeds[testbed]['NIGHTLY_TEST_TIMEOUT']
                if skip_test_results_uploading == None and 'SKIP_TEST_RESULTS_UPLOADING' in self.testbeds[testbed]:
                    logger.info("pipeline has no SKIP_TEST_RESULTS_UPLOADING item, remove {}".format(self.testbeds[testbed]['SKIP_TEST_RESULTS_UPLOADING']))
                    del self.testbeds[testbed]['SKIP_TEST_RESULTS_UPLOADING']
                elif self.skip_upload_result:
                    self.testbeds[testbed]['SKIP_TEST_RESULTS_UPLOADING'] = self.skip_upload_result

                # self.testbeds[testbed]['TESTBED_SPECIFIC'] = testbed_specific
                break

        logger.debug("collect_testbeds_information {}".format(self.testbeds))
        return

    def update_test_image(self, testbed):
        logger.debug("update_test_image {}".format(testbed))
        logger.debug("update_test_image input {} default image {}".format(self.image, self.testbeds[testbed]['image_url']))

        if 'BJW' in self.testbeds[testbed]['image_url']:
            IP_Address = '10.150.22.222'    
        else:
            IP_Address = '10.201.148.43'

        vendor = curr_convert_to_trusty_images_dict[self.testbeds[testbed]['image_url']]['vendor']
        image_name = curr_convert_to_trusty_images_dict[self.testbeds[testbed]['image_url']]['image']
   
        name, ext = image_name.rsplit('.', 1)
        new_name = '{}-{}'.format(name, self.image)
        new_image_name = '{}.{}'.format(new_name, ext)

        # Networking-acs-buildimage-Official/broadcom/internal-202205/tagged/sonic-aboot-broadcom-20220531.05.swi
        # Networking-acs-buildimage-Official/broadcom/internal/sonic-aboot-broadcom-internal.76630385-c5de9bbe18.swi
        image_url = "http://{}/pipelines/Networking-acs-buildimage-Official/{}/{}/{}{}".format(IP_Address, vendor, self.branch, 'tagged/' if self.branch != 'internal' else '', new_image_name)

        # fixme, is it OK for prev image
        self.testbeds[testbed]['image_url'] = image_url

        return

    def get_testbed_pipeline_build_payload(self, testbed):
        logger.debug("get_testbed_pipeline_build_payload {}".format(testbed))
        if self.image:
            self.update_test_image(testbed)

        payload = {
            "resources": {
                "repositories": {
                    "self": {
                        "refName": "refs/heads/{}".format(self.script_branch),
                    }
                }
            },
            "templateParameters" : {
                "TESTBED_NAME" : testbed ,
                "IMAGE_URL" : self.testbeds[testbed]['image_url'],
            }
        }

        if 'TESTBED_SPECIFIC' in self.testbeds[testbed]:
            payload['templateParameters']['TESTBED_SPECIFIC'] = self.testbeds[testbed]['TESTBED_SPECIFIC']

        if 'NIGHTLY_TEST_TIMEOUT' in self.testbeds[testbed]:
            payload['templateParameters']['NIGHTLY_TEST_TIMEOUT'] = self.testbeds[testbed]['NIGHTLY_TEST_TIMEOUT']

        if 'SKIP_TEST_RESULTS_UPLOADING' in self.testbeds[testbed]:
            payload['templateParameters']['SKIP_TEST_RESULTS_UPLOADING'] = self.testbeds[testbed]['SKIP_TEST_RESULTS_UPLOADING']

        return payload

    def trigger_testbeds_pipeline_build(self):
        logger.debug("trigger_testbeds_pipeline_build")    

        self.curr_building_testbed_list = list(self.testbeds.keys())
        if (len(self.curr_building_testbed_list) == 0) :
            logger.info("curr_building_testbed_list is empty ") 
            return

        logger.debug("curr_building_testbed_list {}".format(self.curr_building_testbed_list))
        # for testbed in self.testbeds.keys():
        for testbed in self.curr_building_testbed_list[:]:
            payload = self.get_testbed_pipeline_build_payload(testbed)
            logger.debug("testbed {} payload {}".format(testbed, payload))
            build_id = self.nightly_pipeline_check.trigger_pipeline_build(self.testbeds[testbed]['pipeline_id'] , payload)
            if build_id:
                self.testbeds[testbed]['build_id'] = build_id
                self.testbeds[testbed]['build_status'] = 'inprocess'
            else:
                self.testbeds[testbed]['build_id'] = None
                self.testbeds[testbed]['build_status'] = 'NotStart'
                self.curr_building_testbed_list.remove(testbed)
        return


    def wait_testbeds_pipeline_build_done(self, sleep_time, build_timeout):
        logger.debug("wait_testbeds_pipeline_build_done")    

        if (len(self.curr_building_testbed_list) == 0) :
            logger.info("curr_building_testbed_list is empty, no need to waiting ") 
            return

        start_time = time.time()

        while True:
            time_check = time.time()
            logger.debug("start_time {} time_check {} ".format(start_time, time_check)) 

            if (time_check - start_time) > build_timeout :
                logger.info("build timeout: start time {} current time {} remain testbeds {} ".format(start_time, time_check, self.curr_building_testbed_list))
                break

            if (len(self.curr_building_testbed_list) == 0) :
                logger.info("current build_testbeds_list is empty, break waiting pipeline ") 
                break

            for testbed in self.curr_building_testbed_list[:]:
                build_status = self.nightly_pipeline_check.get_pipeline_build_status(self.testbeds[testbed]['build_id'])
                if build_status:
                    self.testbeds[testbed]['build_status'] = 'Complete'
                    self.curr_building_testbed_list.remove(testbed)


            if len(self.curr_building_testbed_list) > 0:
                time.sleep(sleep_time)
                    
        if len(self.curr_building_testbed_list) != 0:
            logger.error("!!!! ERROR !!!!! curr_building_testbed_list should be emply; {} ".format(self.curr_building_testbed_list))

        return


    def parser_input_testbed_name(self, testbedNames):
        logger.debug("parser_input_testbed_name")    

        if testbedNames and (testbedNames.isspace() == False):
            testbedName_list = testbedNames.split(",")
            logger.info("Input testbed names {}".format(testbedName_list))
            for testbedTmp in testbedName_list:
                testbed = testbedTmp.strip()
                self.testbeds[testbed] = {}
            logger.info("Input testbeds {}".format(self.testbeds))
        else:
            logger.warning("Input testbeds {} incorrect".format(self.testbeds))

        return

    def build_URLs(self, testbed):
        # format input parameter
        testbed_name = str(testbed).strip()
        image_base_branch = str(self.branch).strip()
        private_image_folder = None if self.image_folder is None else str(self.image_folder).strip()
        image_tag = None if self.imagetag is None else str(self.imagetag).strip()
        hwsku = self.lookup_dut_hwsku(testbed_name)
        logger.debug("Building {} device {}'s image URL for branch {}, private folder {}, tag {}".
            format(hwsku, testbed_name, image_base_branch, private_image_folder, image_tag))

        hwsku_package_info = {# {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'image_type': 'aboot', 'suffix': 'dnx', 'lightweight': 'slim', 'extension': 'swi'},
            #
            'ACS-MSN3800':              None,
            #
            # testbed-bjw-can-4600c-1, vms7-t0-4600c-2
            'ACS-MSN4600C':             {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'extension': 'bin'},
            #
            # testbed-bjw-can-7050qx-2, vms18-t0-7050qx-acs-02, vms18-t1-7050qx-acs-03
            'Arista-7050-QX-32S':       {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'image_type': 'aboot', 'lightweight': 'slim', 'extension': 'swi'},
            #
            'Arista-7050-QX32':         None,
            #
            # testbed-bjw-can-7050qx-1, vms24-t1-7050qx-acs-01
            'Arista-7050QX32S-Q32':     {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'image_type': 'aboot', 'lightweight': 'slim', 'extension': 'swi'},
            #
            # vms20-t0-7050cx3-1, vms20-t0-7050cx3-2, vms28-t0-7050-14, vmsvc1-dual-t0-7050-2, vms24-dual-t0-7050-1, vms20-t1-7050cx3-3
            'Arista-7050CX3-32S-C32':   {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'image_type': 'aboot', 'extension': 'swi'},
            #
            # vms21-dual-t0-7050-3
            'Arista-7050CX3-32S-D48C8': {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'image_type': 'aboot', 'extension': 'swi'},
            #
            # vms6-t1-7060, vms63-t1-7060-3
            'Arista-7060CX-32S-C32':    {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'image_type': 'aboot', 'lightweight': 'slim', 'extension': 'swi'},
            #
            # vms63-t0-7060-2, vms63-t0-7060-1, vms6-t0-7060
            'Arista-7060CX-32S-D48C8':  {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'image_type': 'aboot', 'lightweight': 'slim', 'extension': 'swi'},
            #
            'Arista-7060CX-32S-Q32':    None,
            # unknown
            'Arista-7060DX5-32':        None,
            # unknown
            'Arista-7170-64C':          None,
            #
            'Arista-720DT-G48S4':       None,
            #
            # vms2-t1-7260-7
            'Arista-7260CX3-C64':       {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'image_type': 'aboot', 'extension': 'swi'},
            #
            # vms24-t0-7260-2, vms7-t0-7260-2, vms7-t0-7260-1, vms21-dual-t0-7260
            'Arista-7260CX3-D108C8':    {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'image_type': 'aboot', 'extension': 'swi'},
            #
            # vms3-t1-7280
            'Arista-7280CR3-C40':       {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'image_type': 'aboot', 'suffix': 'dnx', 'extension': 'swi'},
            # unknown'
            'Arista-7800R3-48CQ2-C4':   None,
            #
            'Arista-7800R3-48CQ2-C48':  None,
            #
            'Arista-7800R3-48CQM2-C48': None,
            #
            'Arista-7800R3A-36DM2-C36': None,
            #
            'Arista-7800R3A-36DM2-D36': None,
            # unknown
            'Arista-7808R3A-FM':        None,
            #
            # vms20-t1-dx010-6, vms3-t1-dx010-1, vms21-t0-dx010-7
            'Celestica-DX010-C32':      {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'extension': 'bin'},
            #
            # vms7-t0-dx010-5
            'Celestica-DX010-D48C8':    {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'extension': 'bin'},
            #
            'Celestica-E1031-T48S4':    None,
            #
            # testbed-bjw-can-8102-1, vms21-t1-8102-01, vms21-t1-8111-06, vms61-t1-8101-01,  vms61-t1-8101-03
            'Cisco-8101-O32':           {'sai_vendor': 'BRCM', 'image_vendor': 'cisco-8000', 'suffix': 'nosec', 'extension': 'bin'},
            'Cisco-8101-O8C48':         {'sai_vendor': 'BRCM', 'image_vendor': 'cisco-8000', 'suffix': 'nosec', 'extension': 'bin'},
            'Cisco-8102-C64':           {'sai_vendor': 'BRCM', 'image_vendor': 'cisco-8000', 'suffix': 'nosec', 'extension': 'bin'},
            'Cisco-8111-O32':           {'sai_vendor': 'BRCM', 'image_vendor': 'cisco-8000', 'suffix': 'nosec', 'extension': 'bin'},
            'Cisco-8111-O64':           {'sai_vendor': 'BRCM', 'image_vendor': 'cisco-8000', 'suffix': 'nosec', 'extension': 'bin'},
            # unknown
            'Cisco-88-LC0-36FH-M-O36':  None,
            #
            'Cisco-88-LC0-36FH-O36':    None,
            # unknown'
            'Cisco-8800-LC-48H-C48':    None,
            #
            'Cisco-8800-RP':            None,
            # unknown
            'DellEMC-S5232f-C32':       None,
            # unknown
            'Delta-AGC7648':            None,
            #
            # vms13-5-t1-lag, vms11-t0-on-4
            'Force10-S6000':            {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'extension': 'bin'},
            #
            # vms64-t1-s6100-1, vms7-t1-s6100, vms64-t0-s6100-1, vms7-t0-s6100-4, vms7-t0-s6100
            'Force10-S6100':            {'sai_vendor': 'BRCM', 'image_vendor': 'broadcom', 'extension': 'bin'},
            # unknown
            'Force10-Z9100-C32':        None,
            #
            # vms21-t1-2700-2, vms21-t0-2700, vms12-t0-8-lag-2700, vms1-8, testbed-bjw-can-2700-1, testbed-bjw-can-2700-2, vms2-4-t0-2700
            'Mellanox-SN2700':          {'sai_vendor': 'MLNX', 'image_vendor': 'mellanox', 'extension': 'bin'},
            #
            'Mellanox-SN2700-D40C8S8':  None,
            #
            # vms20-t0-sn3800-2
            'Mellanox-SN3800-D112C8':   {'sai_vendor': 'MLNX', 'image_vendor': 'mellanox', 'extension': 'bin'},
            #
            # vms63-t0-dual-4600-1, vms18-t1-msn4600c-acs-1, vms63-t1-4600-5, vms28-t0-4600c-04
            'Mellanox-SN4600C-C64':     {'sai_vendor': 'MLNX', 'image_vendor': 'mellanox', 'extension': 'bin'},
            #
            # vms64-t1-4700-1
            'Mellanox-SN4700-O8C48':    {'sai_vendor': 'MLNX', 'image_vendor': 'mellanox', 'extension': 'bin'},
            #
            'newport':                  None,
            # unknown
            'Nexus-3132-GE-Q32':        None,
            #
            'Nexus-3132-GX-Q32':        None,
            # unknown
            'Nexus-3164':               None,
            #
            'Nokia-7215':               None,
            # unknown
            'Nokia-IXR7250E-36x100G':   None,
            #
            'Nokia-IXR7250E-36x400G':   None,
            #
            'Nokia-IXR7250E-SUP-10':    None,
            #
            'Nokia-M0-7215':            None,
            # unknown
            'Nvidia-9009d3b600CVAA':    None }

        # check condition for building image URL
        require_bjw_lab = self.check_tb_in_require_bjw_lab(testbed_name)
        require_formal_image = True if private_image_folder is None or private_image_folder.lower() in ('', 'none', 'null') else False
        require_image_tag = False if image_tag is None or image_tag.lower() in ('', 'none', 'null') else True
        # Cisco 8102's 202012 image name has no suffix "nosec" or "sec"
        require_ignore_suffix = True if hwsku.startswith('Cisco-8102') and image_base_branch == 'internal-202012' else False
        require_public_image = True if image_base_branch == 'master' else False
        logger.debug("Image URL building condition: require_bjw_lab {}, require_formal_image {}, require_image_tag {}, require_ignore_suffix {}, require_public_image{}".
            format(require_bjw_lab, require_formal_image, require_image_tag, require_ignore_suffix, require_public_image))

        try:
            package_pattern = hwsku_package_info[hwsku]
        except KeyError:
            logger.error('Unsupported HWSKU: {}'.format(hwsku))
            return (None, None, None)
        if package_pattern is None:
            logger.error('Unimplemented HWSKU: {}'.format(hwsku))
            return (None, None, None)

        image_filename = ['sonic']
        if package_pattern.get('image_type', None):image_filename.append(package_pattern['image_type'])
        image_filename.append(package_pattern['image_vendor'])
        if package_pattern.get('suffix', None) and not require_ignore_suffix: image_filename.append(package_pattern['suffix'])
        if package_pattern.get('lightweight', None): image_filename.append(package_pattern['lightweight'])
        prev_image_filename = '-'.join(image_filename)
        if require_image_tag: image_filename.append(image_tag)
        image_filename = '-'.join(image_filename)

        base_url = ['http:/']
        base_url.append('10.150.22.222') if require_bjw_lab else base_url.append('10.201.148.43')
        if require_public_image:
            base_url.append('mssonic-public-pipelines/Azure.sonic-buildimage.official.{}'.format(package_pattern['image_vendor'])) 
        else:
            base_url.append('pipelines/Networking-acs-buildimage-Official/{}'.format(package_pattern['image_vendor']))
        base_url.append(image_base_branch) if require_formal_image else base_url.append(private_image_folder)
        if require_public_image: base_url.append(package_pattern['image_vendor'])
        # Networking-acs-buildimage-Official/broadcom/internal-202205/tagged/sonic-aboot-broadcom-20220531.05.swi
        # Networking-acs-buildimage-Official/broadcom/internal/sonic-aboot-broadcom-internal.76630385-c5de9bbe18.swi
        if image_base_branch != 'internal': base_url.append('tagged')
        base_url = '/'.join(base_url)

        image_url = base_url + '/' + image_filename + '.' + package_pattern['extension']
        prev_image_url = base_url + '/' + prev_image_filename + '.' + package_pattern['extension'] + '.PREV.1'
        if 'lightweight' in package_pattern and package_pattern['lightweight'] == 'slim':
            prev_image_url = 'http://10.201.148.43/pipelines/Networking-acs-buildimage-Official/broadcom/internal-201811/tagged/sonic-aboot-broadcom.swi'
            if require_bjw_lab: prev_image_url = prev_image_url.replace('10.201.148.43', '10.150.22.222')
        else:
            prev_image_url = None

        saithrift_macro = ['BJW_SAITHRIFT'] if require_bjw_lab else ['SAITHRIFT']
        saithrift_macro.append(package_pattern['sai_vendor'])
        if image_base_branch == 'master':
            saithrift_macro.append('PUBLIC')
        elif image_base_branch == 'internal':
            saithrift_macro.append('INTERNAL')
        else:
            saithrift_macro.append(image_base_branch.split('-')[-1])
        saithrift_macro = '$(' + '_'.join(saithrift_macro) + ')'

        logger.info("Image URL is build out for {}:\n\t{}\n\t{}\n\t{}".format(testbed_name, image_url, prev_image_url, saithrift_macro))

        self.testbeds[testbed_name]['image_url'] = image_url


        AGENT_POOL = 'nightly-bjw' if require_bjw_lab else 'nightly'

        return (image_url, prev_image_url, saithrift_macro, AGENT_POOL)


    def build_case_verify_pipeline_payload(self, testbed):
        logger.debug("build_case_verify_pipeline_payload {}".format(testbed))
        image_url, prev_image_url, saithrift_macro, agent_pool = self.build_URLs(testbed)

        if image_url is None:
            return None

        payload = {
            "resources": {
                "repositories": {
                    "self": {
                        "refName": "refs/heads/{}".format(self.script_branch),
                    }
                }
            },
            "templateParameters" : {
                "TESTBED_NAME" : testbed ,
                "IMAGE_URL" : image_url,
                "PY_SAITHRIFT_URL" : saithrift_macro,
                "TESTBED_SPECIFIC" : self.testbed_specific ,
                "TEST_BRIEF": self.test_brief,
                "NIGHTLY_TEST_TIMEOUT" : self.pipeline_timeout ,
                "LOCK_POLLING_TIMEOUT" : self.lock_timeout ,
                "FORCE_LOCK": False,
                "DOCKER_FOLDER_SIZE" : '3500M',
                "SKIP_TEST_RESULTS_UPLOADING" : self.skip_upload_result ,
                "AGENT_POOL" : agent_pool ,
            }
        }
        if prev_image_url:
            payload['templateParameters']['PREV_IMAGE_URL'] = prev_image_url
        logger.debug("build_case_verify_pipeline_payload payload {}".format(payload))
        return payload

    def trigger_case_verify_pipeline_build(self):
        logger.debug("trigger_case_verify_pipeline_build")    

        self.curr_building_testbed_list = list(self.testbeds.keys())
        if (len(self.curr_building_testbed_list) == 0) :
            logger.info("curr_building_testbed_list is empty ") 
            return

        logger.debug("curr_building_testbed_list {}".format(self.curr_building_testbed_list))
        # for testbed in self.testbeds.keys():
        for testbed in self.curr_building_testbed_list[:]:
            payload = self.build_case_verify_pipeline_payload(testbed)
            logger.debug("testbed {} payload {}".format(testbed, payload))
            build_id = self.nightly_pipeline_check.trigger_pipeline_build(self.case_verify_pipeline_id, payload)
            if build_id:
                self.testbeds[testbed]['build_id'] = build_id
                self.testbeds[testbed]['build_status'] = 'inprocess'
            else:
                self.testbeds[testbed]['build_id'] = None
                self.testbeds[testbed]['build_status'] = 'NotStart'
                self.curr_building_testbed_list.remove(testbed)
        return



if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Completeness level')
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="nightly hawk verify")

    parser.add_argument(
        '-v', '--verbose', help='Set logging level', type=str,
        required=False, default='DEBUG'
    )

    parser.add_argument(
        '-b', '--imagebranch', help='input image branch name', type=str,
        required=True
    )

    parser.add_argument(
        '-t', '--verifytype', help='feature branch verify or cases verify', type=str,
        required=True
    )

    parser.add_argument(
        '-s', '--scriptbranch', help='input mgmt script branch name', type=str,
        required=True
    )

    parser.add_argument(
        '-f', '--imagefolder', help='input image path', type=str,
        required=True
    )

    parser.add_argument(
        '-p', '--parameterspecific', help='input Testbed specific parameter', type=str,
        required=True
    )

    parser.add_argument(
        '-r', '--resultignore', help='set if upload test result to kusto', type=bool,
        required=True
    )

    parser.add_argument(
        '-i', '--imagetag', help='input image tag', type=str,
        required=False, default=None
    )

    parser.add_argument(
        '-n', '--testbedNames', help='input testbed names, if no input list, auto run', type=str,
        required=False
    )

    parser.add_argument(
        '-l', '--library', help='using library to collect testbed names', type=str,
        required=False
    )

    parser.add_argument(
        '--lockpollingtimeout', help='lock testbed polling timeout value', type=str,
        required=False
    )

    parser.add_argument(
        '--pipelinetimeout', help='pipeline running timeout value', type=str,
        required=False
    )

    parser.add_argument(
        '--testbrief', help='test breif', type=str,
        required=False
    )

    logger.info("----- Nightly Hawk verify ----- ")
    args = parser.parse_args()
    for arg in vars(args):
        logger.info("input parameter {}: {}".format(arg, getattr(args, arg)))

    # if args.image and (args.image.isspace() == False):
    #     # fixme, how to check wehther image tag is valid
    #     image = args.image
    # else:
    #     image = None

    if args.verbose and (args.verbose.isspace() == False):
        logging_lever = args.verbose.lower()
        logger.info("Input logging_lever {}".format(logging_lever))
        if logging_lever == 'debug':
            logger.setLevel(logging.DEBUG)
        elif logging_lever == 'info':
            logger.setLevel(logging.INFO)
        elif logging_lever == 'error':
            logger.setLevel(logging.ERROR)

    if args.lockpollingtimeout and (args.lockpollingtimeout.isspace() == False):
        lockpollingtimeout = args.lockpollingtimeout
    else:
        lockpollingtimeout = 7200

    if args.pipelinetimeout and (args.pipelinetimeout.isspace() == False):
        pipelinetimeout = args.pipelinetimeout
    else:
        pipelinetimeout = 1800        

    testbrief = args.testbrief if args.testbrief else 'Test-Brief'

    branch_verify = Nightly_hawk_branch_verify(verbose=args.verbose, test_brief=testbrief, branch=args.imagebranch, type=args.verifytype, script=args.scriptbranch, image=args.imagefolder, imagetag=args.imagetag, specific=args.parameterspecific, skip=args.resultignore, lock_timeout=lockpollingtimeout, pipeline_timeout=pipelinetimeout)

    if args.verifytype == 'branch_verify':
        logger.error(" !!! ERROR: branch_verify not support anymore after pipeline migrated to Elastic! ")
        
        '''
        branch_verify.pipeline_parser_analyzer_dict = branch_verify.nightly_pipeline_check.collect_nightly_build_pipelines('nightly')

        if args.testbedNames and (args.testbedNames.isspace() == False):
            logger.info("testbedNames {}".format(args.testbedNames))
            logger.info("Input testbed names {}, will run test on these testbeds".format(args.testbedNames))
            branch_verify.testbedNames = args.testbedNames
            testbedName_list = branch_verify.testbedNames.split(",")
            logger.info("Input testbed names {}, will run test on these testbeds".format(testbedName_list))
            for testbedTmp in testbedName_list:
                logger.info("testbedTmp {}".format(testbedTmp))
                testbed = testbedTmp.strip()
                logger.info("testbed {}".format(testbed))
                branch_verify.testbeds[testbed] = {}

        elif args.library and (args.library.isspace() == False):
            library_string = args.library
            logger.info("Input library {}".format(library_string))

            #  -l '{"testbed-bjw-can-7050qx-1":{"TESTBED_SPECIFIC": "-I debug", "NIGHTLY_TEST_TIMEOUT": "3600"}, "vms24-t1-7050qx-acs-01":{"TESTBED_SPECIFIC": "-S platform", "NIGHTLY_TEST_TIMEOUT": "3200"}}'
            library_json = json.loads(library_string)
            # logger.info("Input library_json {}".format(library_json))
            for testbed_name, build_info in library_json.items():
                logger.info("testbed_name {}: {}".format(testbed_name, build_info))
                testbed = testbed_name.strip()
                branch_verify.testbeds[testbed] = {}
                for key, value in build_info.items():
                    branch_verify.testbeds[testbed][key] = value

        else:
            logger.info("Input testbed names and library None")
            logger.info("Collect nightly tests pipeline information")
            # branch_verify.get_testbeds(args.topo)


        logger.info("Collected testbeds {}".format(branch_verify.testbeds))
        
        # collect testbeds pipeline information
        branch_verify.collect_testbeds_information()

        # trigger pipeline
        branch_verify.trigger_testbeds_pipeline_build()
        logger.info("testbeds {}".format(branch_verify.testbeds))

        # waiting pipeline done
        branch_verify.wait_testbeds_pipeline_build_done(10*60, 32*60*60)
        logger.info("testbeds {}".format(branch_verify.testbeds))
        '''

    elif args.verifytype == 'case_verify':
        branch_verify.parser_input_testbed_name(args.testbedNames)
        branch_verify.trigger_case_verify_pipeline_build()

    else:
        logger.warning("Input verifytype {} invalid".format(args.verifytype))

    logger.info("Nightly_hawk_branch_verify complete ")

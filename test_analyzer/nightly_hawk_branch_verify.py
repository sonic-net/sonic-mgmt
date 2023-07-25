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


class Nightly_hawk_branch_verify(object):
    def __init__(self, verbose = False, branch = None, image = None, script=None, specific=None, skip=False):
        self.verbose = verbose
        self.branch = branch
        self.script_branch = script
        self.testbed_specific = specific
        self.skip_upload_result = skip
        self.image = image
        self.testbeds = {}
        self.curr_building_testbed_list = []
        self.pipeline_parser_analyzer_dict = {}
        self.nightly_pipeline_check = NightlyPipelineCheck()

        self.pipeline_parser_analyzer_dict = self.nightly_pipeline_check.collect_nightly_build_pipelines()

        # with open('pipeline_parser_dict_debug_branch_verify.json') as f:
        # # with open('pipeline_parser_dict_debug.json') as f:
        #     logger.info("parser_pipeline_info using cache file")
        #     self.pipeline_parser_analyzer_dict = json.load(f)

        logger.debug("Get all nightly test pipeline information: {}".format(self.pipeline_parser_analyzer_dict))


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
                _, _, _, _, testbed_specific, nightly_test_timeout, skip_test_results_uploading = self.nightly_pipeline_check.parser_nightly_pipeline_yml_File(yml)
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


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Completeness level')
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="nightly hawk pipeline analyzer")

    parser.add_argument(
        '-v', '--verbose', help='Set logging level', type=str,
        required=False, default='DEBUG'
    )

    parser.add_argument(
        '-b', '--branch', help='input branch name', type=str,
        required=True
    )

    parser.add_argument(
        '-s', '--script', help='input mgmt script branch name', type=str,
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
        '-i', '--image', help='input image name', type=str,
        required=False, default=None
    )

    parser.add_argument(
        '-t', '--topo', help='input topo name', type=str,
        required=False, default='all'
    )

    parser.add_argument(
        '-n', '--testbedNames', help='input testbed names, if no input list, auto run', type=str,
        required=False
    )

    parser.add_argument(
        '-f', '--force', help='force run the test', action='store_true',
        required=False
    )

    parser.add_argument(
        '-l', '--library', help='using library to collect testbed names', type=str,
        required=False
    )    

    args = parser.parse_args()
    logger.info("Verify {} branch with logging lever {}".format(args.branch, args.verbose))
    logger.info("testbedNames {} library {} image {} topo {} force {}".format(args.testbedNames, args.library, args.image, args.topo, args.force))

    if args.image and (args.image.isspace() == False):
        # fixme, how to check wehther image tag is valid
        image = args.image
    else:
        image = None

    if args.verbose and (args.verbose.isspace() == False):
        logging_lever = args.verbose.lower()
        logger.info("Input logging_lever {}".format(logging_lever))
        if logging_lever == 'debug':
            logger.setLevel(logging.DEBUG)
        elif logging_lever == 'info':
            logger.setLevel(logging.INFO)
        elif logging_lever == 'error':
            logger.setLevel(logging.ERROR)

    branch_verify = Nightly_hawk_branch_verify(verbose=args.verbose, branch=args.branch, image=args.image, script=args.script, specific=args.parameterspecific, skip=args.resultignore)


    

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
        branch_verify.get_testbeds(args.topo)

    logger.info("Collected testbeds {}".format(branch_verify.testbeds))
    
    # collect testbeds pipeline information
    branch_verify.collect_testbeds_information()

    # trigger pipeline
    branch_verify.trigger_testbeds_pipeline_build()
    logger.info("testbeds {}".format(branch_verify.testbeds))

    # waiting pipeline done
    branch_verify.wait_testbeds_pipeline_build_done(10*60, 32*60*60)
    logger.info("testbeds {}".format(branch_verify.testbeds))



    logger.info("Nightly_hawk_branch_verify complete ")

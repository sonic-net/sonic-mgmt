#!/bin/env python

import argparse
import json
import logging
import os
import sys
import requests
import time
import datetime
import tempfile
import yaml
import re

from azure.kusto.data import KustoConnectionStringBuilder, KustoClient
from azure.kusto.ingest import IngestionProperties

try:
    from azure.kusto.ingest import KustoIngestClient
except ImportError:
    from azure.kusto.ingest import QueuedIngestClient as KustoIngestClient

try:
    from azure.kusto.ingest import DataFormat
except ImportError:
    from azure.kusto.data.data_format import DataFormat

NIGHTLY_HAWK_DIR = os.path.abspath(os.path.dirname(__file__))
SONIC_MGMT_DIR = os.path.dirname(NIGHTLY_HAWK_DIR)
ANSIBLE_DIR = os.path.join(SONIC_MGMT_DIR, 'ansible') 
NIGHTLY_PIPELINE_YML_DIR = os.path.join(SONIC_MGMT_DIR, '.azure-pipelines/nightly') 
TESTBED_FILE = os.path.join(SONIC_MGMT_DIR, 'ansible/testbed.yaml') 

DATABASE = 'SonicTestData'

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s %(filename)s:%(name)s:%(lineno)d %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class KustoChecker(object):
    def __init__(self, cluster, tenant_id, client_id, client_key, database):
        self.cluster = cluster
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_key = client_key
        self.database = database

        self.logger = logging.getLogger('KustoChecker')

        kcsb = KustoConnectionStringBuilder.with_aad_application_key_authentication(
            self.cluster,
            self.client_id,
            self.client_key,
            self.tenant_id
            )

        self.client = KustoClient(kcsb)

    def query(self, query):
        self.logger.debug('Query String: {}'.format(query))
        return self.client.execute(self.database, query)

    def query_unhealthy_testbeds(self, date):
        query_str = '''
            TestReportPipeline
            | where UploadTimestamp > ago({date})
            | where FailedTasks contains "Run Tests" or FailedTasks contains "Upgrade Image" or FailedTasks contains "Deploy Minigraph" or CancelledTasks contains "Run Tests"
            | where TestbedName != ''
            | distinct StartTimestamp, TestbedName, FailedTasks
            '''.format(date=date)
        return self.query(query_str)

    def query_autoRecovery_testbeds(self, date):
        query_str = '''
            TestbedAutoRecoveryData
            | where UTCTimestamp > ago({date})
            | order by UTCTimestamp asc
            | distinct UTCTimestamp, TestbedName, DutName, DutIP, Console, TriggerIcM ,Priority, Summary
            '''.format(date=date)
        return self.query(query_str)

    def query_build_test_result(self, build_id):
        query_str = '''
            FlatTestReportViewLatest
            | where StartTimeUTC > ago(30d)
            | where BuildId == '{build_id}'
            | extend Comments = " "
            | distinct StartTimeUTC, TestbedName, OSVersion, BuildId, Result, FullTestPath, Comments, Summary, StartTime, Runtime, ModulePath, TestCase
            | sort by StartTime asc 
            '''.format(build_id=build_id)
        return self.query(query_str)


class KustoUploader(object):
    def __init__(self, cluster, tenant_id, client_id, client_key, database):
        self.cluster = cluster
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_key = client_key
        self.database = database

        self.logger = logging.getLogger('KustoUploader')

        kcsb = KustoConnectionStringBuilder.with_aad_application_key_authentication(
            self.cluster,
            self.client_id,
            self.client_key,
            self.tenant_id
            )

        self.ingestion_client = KustoIngestClient(kcsb)


    def upload_file(self, file_name, kusto_table, ingestion_mapping_reference):
        props = IngestionProperties(
            database=self.database,
            table=kusto_table,
            data_format=DataFormat.JSON,
            ingestion_mapping_reference=ingestion_mapping_reference
        )

        logger.info("Ingest to backup cluster...")
        self.ingestion_client.ingest_from_file(file_name, ingestion_properties=props) 

        return


class TbShare(object):
    def __init__(self):
        self.proxies = {'http': os.environ.get('http_proxy'), 'https': os.environ.get('http_proxy')}
        self.token = self.get_token_from_elastictest()
        if not self.token:
            raise RuntimeError('TbShare no token')

        logger.debug("init TbShare token {} ".format(self.token)) 



    def get_token(self):
        client_id = os.environ.get('TBSHARE_AAD_CLIENT_ID')
        client_secret = os.environ.get('TBSHARE_AAD_CLIENT_SECRET')

        if not client_id or not client_secret:
            logger.info("Need environment variables: TBSHARE_AAD_CLIENT_ID, TBSHARE_AAD_CLIENT_SECRET")
            return None

        token_url = 'https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/token'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        payload = {
            'resource': 'https://tbshare.azurewebsites.net',
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret
        }

        try:
            for i in range(5):
                response = requests.post(token_url, headers=headers, data=payload, proxies=self.proxies, timeout=30)
                if response.status_code == requests.codes.ok:
                    break
                time.sleep(1)

            token = None
            if response.status_code == requests.codes.ok:
                response_data = response.json()
                if (response_data.get('access_token', None)):
                    token = response_data['access_token']
            else:
                logger.debug("get token failed return code {} ".format(response.status_code))

            logger.debug("get token token {} ".format(token))
            return token
        except Exception as e:
            return None


    def get_token_from_elastictest(self):
        token_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/token'.format(os.environ.get('ELASTICTEST_MSAL_TENANT'))
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        payload = {
            'grant_type': 'client_credentials',
            'client_id': os.environ.get('ELASTICTEST_MSAL_CLIENT_ID'),
            'client_secret': os.environ.get('ELASTICTEST_MSAL_SECRET_VALUE'),
            'scope': os.environ.get('ELASTICTEST_MSAL_SCOPE')
        }

        logger.debug("get token token_url {} ".format(token_url))
        logger.debug("get token headers {} ".format(headers))
        logger.debug("get token payload {} ".format(payload))

        try:
            resp = requests.post(token_url, headers=headers, data=payload, timeout=10).json()
            
            # resp = requests.post(token_url, headers=headers, data=payload, timeout=10)

            logger.info("get return code {} ".format(resp))

            return resp['access_token']
        except Exception as e:
            print('Get token failed with exception: {}'.format(repr(e)))
        return None


    def get_testbed(self, testbed):

        url = 'https://tbshare.azurewebsites.net/api/testbed/{}'.format(testbed)
        headers = {
            'Authorization': 'Bearer ' + self.token
        }

        try:
            for i in range(10):
                response = requests.get(url, headers=headers, proxies=self.proxies, timeout=30)
                logger.info("get testbed info return code {} ".format(response.status_code))
                if response.status_code == requests.codes.ok:
                    break
                time.sleep(1)

            testbed_info = {}
            if response.status_code == requests.codes.ok:
                testbed_info = response.json()
            else:
                logger.info("get testbed info failed return code {} ".format(response.status_code))

            return testbed_info
        except Exception as e:
            return {}


    def lock_release_api(self, testbed, action, hours, user, reason, force, absolute):

        logger.info('[Elastictest] {} testbed {} force {} absolute {} '.format(action, testbed, force, absolute))
        try:
            lock_tb_num = 1
            data = {
                "testbed_requirement": {
                    'platform': 'PHYSICAL',
                    'name': [testbed],
                    'min': lock_tb_num,
                    'max': lock_tb_num
                },
                "hours": hours,
                "requester_id": user,
                'lock_reason': reason,
                'absolute_lock': absolute,
                'force_lock': force,

            }
            if action == 'release':
                data = {
                    'testbed_names': [testbed],
                    'force_release': force,
                    "requester_id": user,
                }

            headers = {
                'Authorization': 'Bearer {}'.format(self.get_token_from_elastictest())
            }
            resp = requests.post("{}/{}".format(os.environ.get("ELASTICTEST_MGMT_TESTBED_URL"), action),
                                json=data,
                                headers=headers).json()

            if 'failed' in resp and resp['failed']:
                logger.info('[Elastictest] {} testbed {} failed'.format(action, testbed))
                if 'msg' in resp:
                    print(resp['msg'])
                return 2
            else:
                if not resp['success']:
                    logger.info('[Elastictest] Lock testbeds failed with error: {}'.format(resp['errmsg']))
                    return 2
                if action == "lock":
                    if resp['data'] is None or (len(resp['data']) < lock_tb_num):
                        logger.info("[Elastictest] Lock testbed failed, can't lock expected testbed")
                        return 2
                logger.info('[Elastictest] {} testbed {} succeeded'.format(action, testbed))
                return 0

        except Exception as e:
            logger.info('[Elastictest] {} testbed {} failed with exception: {}'.format(action, testbed, repr(e)))
            return 3


class NightlyPipelineCheck(object):
    def __init__(self):
        TOKEN = os.environ.get('AZURE_DEVOPS_MSSONIC_TOKEN')
        if not TOKEN:
            logger.error("Get token failed, Must export environment variable AZURE_DEVOPS_MSSONIC_TOKEN")
            raise RuntimeError('Azure devops no token')
        self.token = ('', TOKEN)
        self.__nightly_pipelines_yml_dict = {}
        self.__pipeline_parser_analyzer_dict = {}


    def get_token(self):
        client_id = os.environ.get('TBSHARE_AAD_CLIENT_ID')
        client_secret = os.environ.get('TBSHARE_AAD_CLIENT_SECRET')


    def get_pipelines_info(self, pipeline_id):
        get_pipeline_build_url = "https://dev.azure.com/mssonic/internal/_apis/pipelines/" + str(pipeline_id) + "?api-version=6.0-preview.1"

        file_name = None
        pipeline_name = None
        path = None

        get_response = requests.get(get_pipeline_build_url, auth=self.token)
        if get_response.status_code == 200:
            pipeline_id_records = get_response.json()

            file_name = os.path.basename(pipeline_id_records['configuration']['path'])
            pipeline_name = pipeline_id_records['name']
            path = pipeline_id_records['configuration']['path']
        else:
            logger.error("get_pipelines_ids failed: code {} ".format(get_response.status_code))

        # logger.info("pipeline id {} : {} {} {}   ".format(pipeline_id, file_name, pipeline_name, path))
        return file_name, pipeline_name, path

    def decode_cron(self, cron_expression):
        parts = cron_expression.split()
        if len(parts) != 5:
            return cron_expression
        minute = int(parts[0])
        hour = int(parts[1])
        day_of_month = parts[2]
        month = parts[3]
        day_of_week = parts[4].split(',')

        new_hour = hour + 8
        day_over = ""
        if new_hour >= 24:
            new_hour -= 24
            # day_of_week = [int(x) + 1 for x in day_of_week]
            day_over = "+1"

        schedule = "{:02d}:{:02d} {} {}".format(new_hour, minute, day_of_week, day_over)
        logger.debug("cron_expression {} -> {} ".format(cron_expression, schedule))
        return schedule


    def parser_nightly_pipeline_yml_File(self, fileName):
        logger.info("fileName{} ".format(fileName))
        with open(fileName) as f:
            pipeline_file_dict = yaml.safe_load(f)

            # logger.info("pipeline_file_dict{} ".format(pipeline_file_dict))
            # logger.info("pipeline_file_dict {} ".format(pipeline_file_dict))
            # for key,value in pipeline_file_dict.items():
            #     logger.info("{} : {} {}".format(key, value, type(value)))
            
            testbed_name = None
            image_url = None
            branch_name = None
            schedules = None
            testbed_specific = None
            nightly_test_timeout = None            

            schedules = pipeline_file_dict.get('schedules', None)
            parameters = pipeline_file_dict.get('parameters', None)
            if not schedules or not parameters:
                logger.info("file {} seems not a nightly pipeline yml file ".format(fileName))
                return None, None, None, None, None, None

            for para in pipeline_file_dict['parameters']:
                if para['name'] == 'TESTBED_NAME':
                    # logger.info("{}".format(para['default']))
                    testbed_name = para['default']
                if para['name'] == 'IMAGE_URL':
                    # logger.info("{}".format(para['default']))
                    image_url = para['default']   
                if para['name'] == 'TESTBED_SPECIFIC':
                    # logger.info("{}".format(para['default']))
                    testbed_specific = para['default']   
                if para['name'] == 'NIGHTLY_TEST_TIMEOUT':
                    # logger.info("{}".format(para['default']))
                    nightly_test_timeout = para['default']   


            if len(pipeline_file_dict['schedules']) > 1 or len(pipeline_file_dict['schedules'][0]['branches']['include']) > 1:
                logger.info("schedules ERROR {}".format(pipeline_file_dict['schedules']))
                raise RuntimeError('schedules ERROR {} '.format(pipeline_file_dict['schedules']))
            branch_name = pipeline_file_dict['schedules'][0]['branches']['include'][0]
            schedules = self.decode_cron(pipeline_file_dict['schedules'][0]['cron'])

            return testbed_name, branch_name, image_url, schedules, testbed_specific, nightly_test_timeout


    def get_pipeline_ids_from_azure(self):
        """
        request to get all pipeline IDs
        """
        # get_pipeline_ids_url = "https://dev.azure.com/mssonic/internal/_apis/pipelines/?api-version=6.0-preview.1"
        get_pipeline_ids_url = "https://dev.azure.com/mssonic/internal/_apis//build/definitions"

        logger.debug("get pipeline build status, url {} ".format(get_pipeline_ids_url))

        # parser nightly pipeline build from azure
        pipeline_ids_records = None
        get_response = requests.get(get_pipeline_ids_url, auth=self.token)
        if get_response.status_code == 200:
            pipeline_ids_records = get_response.json()
            logger.debug("get pipeline_ids_records {}   ".format((pipeline_ids_records)))
        else:
            logger.error("get_pipelines_ids failed: code {} ".format(get_response.status_code))

        return pipeline_ids_records


    def get_pipeline_yml_from_code(self):
        """
        parser all yml files in nightly folder, and save every nightly yml file into self.nightly_pipelines_yml_dict
        key : yml name
        value: dict including testbed name, branch, schedule, image_url which in yml file

        'testbed-bjw-can-720dt-1.yml': {
            'testbed_name': 'testbed-bjw-can-720dt-1',
            'branch': 'internal-202205',
            'schedule': '0 11 * * 6',
            'image_url': '$(BJW_IMAGE_BRCM_ABOOT_202205)'
        },
        ......
        """
        nightly_pipelines_yml_dict = {}
        for home, dirs, files in os.walk(NIGHTLY_PIPELINE_YML_DIR):
            for file in files:
                # logger.info("home {} dirs {} file {} ".format(home, dirs, files))
                if file.endswith('.yml'):
                    testbed_name, branch_name, image_url, schedules, _, _ = self.parser_nightly_pipeline_yml_File(os.path.join(home, file))
                    logger.debug("file {} testbed_name {} branch_name {} image_url {} schedules {}".format(file, testbed_name, branch_name, image_url, schedules))
                    if not nightly_pipelines_yml_dict.get(file, None):
                        if testbed_name and branch_name and schedules:
                            nightly_pipelines_yml_dict[file] = {
                                                                        'testbed_name': testbed_name,
                                                                        'branch': branch_name,
                                                                        'schedule': schedules,
                                                                        'image_url': image_url
                                                                    }
                    else:
                        logger.warning("file {} has more than 1 nightly builds ".format(file))
                        logger.info("pre:  testbed_name {} branch_name {} image_url {} schedules {}".format(nightly_pipelines_yml_dict[file]['testbed_name'], \
                                                                                                           nightly_pipelines_yml_dict[file]['branch'], \
                                                                                                           nightly_pipelines_yml_dict[file]['schedule'], \
                                                                                                           nightly_pipelines_yml_dict[file]['image_url']))
                        logger.info("curr: testbed_name {} branch_name {} image_url {} schedules {}".format(testbed_name, branch_name, image_url, schedules))

        logger.info("nightly_pipelines_yml_dict {}".format(nightly_pipelines_yml_dict))
        return nightly_pipelines_yml_dict

    
    def collect_nightly_build_pipelines(self):
        # get pipeline ids from azure pipeline
        pipeline_ids_records = self.get_pipeline_ids_from_azure()
        if pipeline_ids_records == None:
            logger.error("pipeline_ids_records is None, get nightly pipeline ids failed ")
            raise RuntimeError('Azure devops no token')
        
        # get pipeline yml files from code
        nightly_pipelines_yml_dict = self.get_pipeline_yml_from_code()
    
        pipeline_parser_analyzer_dict = {}
        # collect current nightly pipeline build 
        logger.info("pipeline build pipeline_ids_records count {}   ".format((pipeline_ids_records['count'])))
        # for i in range(pipeline_ids_records['count']):
        for pipeline_info in pipeline_ids_records['value']:
            logger.warning("pipeline_info {} ".format(pipeline_info))
            if 'path' in pipeline_info and pipeline_info['path'].startswith('\\Nightly') and not pipeline_info['path'].startswith('\\Nightly-Hawk') and not '\\Disabled' in pipeline_info['path']:
                file_name, pipeline_name, path = self.get_pipelines_info(pipeline_info['id'])
                if file_name == None and pipeline_name == None and path == None :
                    logger.warning("get_pipelines_id {} failed ".format(pipeline_info['id']))
                    continue

                logger.warning("file_name {} pipeline_name {} path {} ".format(file_name, pipeline_name, path))
                if file_name in nightly_pipelines_yml_dict.keys():
                    pipeline_id = pipeline_info['id']

                    testbed_name = nightly_pipelines_yml_dict[file_name]['testbed_name']
                    branch = nightly_pipelines_yml_dict[file_name]['branch']

                    if nightly_pipelines_yml_dict[file_name]['image_url'] == None or nightly_pipelines_yml_dict[file_name]['image_url'] == '':
                        image_url = None
                    else:
                        image_url = nightly_pipelines_yml_dict[file_name]['image_url']

                    if testbed_name not in pipeline_parser_analyzer_dict.keys():
                        pipeline_parser_analyzer_dict[testbed_name] = {}

                    if branch == 'internal' and 'master' in path or (image_url and 'PUBLIC' in image_url):
                        logger.debug("testbed {} testbed_name {} image_url {} path {}  ".format(branch, testbed_name, image_url, path)) 
                        branch = 'master'

                    if (image_url and '201911' in image_url):
                        if branch != 'internal-202012' or '201911' not in pipeline_name:
                            logger.warning(" !!! warning !!! mismatch testbed {} testbed_name {} image_url {} path {}  ".format(branch, testbed_name, image_url, path)) 
                        branch = 'internal-201911'

                    if (image_url and '202012' in image_url):
                        if branch != 'internal-202012' or '202012' not in pipeline_name:
                            logger.warning(" !!! warning !!! mismatch testbed {} testbed_name {} image_url {} path {}  ".format(branch, testbed_name, image_url, path)) 

                    if (image_url and '202225' in image_url):
                        if branch != 'internal-202205' or '202205' not in pipeline_name:
                            logger.warning(" !!! warning !!! mismatch testbed {} testbed_name {} image_url {} path {}  ".format(branch, testbed_name, image_url, path)) 

                    if (image_url and 'INTERNAL' in image_url):
                        if (branch != 'internal' or 'internal' not in pipeline_name) and (branch != 'internal' or 'internal' not in pipeline_name):
                            logger.warning(" !!! warning !!! mismatch testbed {} testbed_name {} image_url {} path {}  ".format(branch, testbed_name, image_url, path)) 

                    if (image_url and 'PUBLIC' in image_url):
                        if branch != 'master' or 'master' not in pipeline_name:
                            logger.warning(" !!! warning !!! mismatch testbed {} testbed_name {} image_url {} path {}  ".format(branch, testbed_name, image_url, path)) 




                    if branch not in pipeline_parser_analyzer_dict[testbed_name].keys():
                        pipeline_parser_analyzer_dict[testbed_name][branch] = {}

                    if file_name not in pipeline_parser_analyzer_dict[testbed_name][branch].keys():
                        pipeline_parser_analyzer_dict[testbed_name][branch][file_name] = {}

                    pipeline_parser_analyzer_dict[testbed_name][branch][file_name] = { 
                                                                                        'pipeline_name' : pipeline_name, 
                                                                                        'pipeline_id' : pipeline_id, 
                                                                                        'path' : path, 
                                                                                        'testbed_name' : testbed_name, 
                                                                                        'branch' : branch, 
                                                                                        'schedule' : nightly_pipelines_yml_dict[file_name]['schedule'], 
                                                                                        'image_url' : image_url
                                                                                     }
        logger.info("pipeline_parser_analyzer_dict {}".format(pipeline_parser_analyzer_dict))
        json_object = json.dumps(pipeline_parser_analyzer_dict, indent = 4)
        with open("pipeline_parser_dict_debug.json", "w") as out_file:
            out_file.write(json_object)

        logger.info("nightly build testbeds {}".format(pipeline_parser_analyzer_dict.keys()))

        return pipeline_parser_analyzer_dict


    def get_pipeline_build_result_by_build_id(self, pipeline_id, build_id):
        # logger.debug("get build result pipeline_id {} build_id {} ".format(pipeline_id, build_id))

        pipeline_url = "https://dev.azure.com/mssonic/internal/_apis/build/builds/" + str(build_id) + "/timeline?api-version=5.1"

        try:
            for i in range(5):
                build_response = requests.get(pipeline_url, auth=self.token)
                if build_response.status_code == requests.codes.ok:
                    break
                logger.warning("build result pipeline_id {} build_id {}, try {}".format(pipeline_id, build_id, i))
                time.sleep(1)

            get_build_records = None
            if build_response.status_code == requests.codes.ok:
                get_build_records = build_response.json()
            else:
                logger.error("get_single_pipelines_detail failed: code {} pileline {}  build id {} ".format(build_response.status_code, pipeline_id, build_id))
            return get_build_records

        except Exception as e:
            return None

    def get_pipeline_status_result_by_pipeline_id(self, pipeline_id):
        pipeline_url = "https://dev.azure.com/mssonic/internal/_apis/pipelines/" + str(pipeline_id) + "/runs?api-version=6.0-preview.1"

        try:
            for i in range(5):
                build_response = requests.get(pipeline_url, auth=self.token)
                if build_response.status_code == requests.codes.ok:
                    break
                logger.warning("build result pipeline_id {}, try {}".format(pipeline_id, i))
                time.sleep(1)

            if build_response.status_code == requests.codes.ok:
                pipeline_dict = yaml.safe_load(build_response.text)
                # logger.info("pipeline_id {} dict {}  ".format(pipeline_id, pipeline_dict))
                parser_count = pipeline_dict['count']
                parser_value = pipeline_dict['value']
                logger.info("pipeline_id {} parser_count {} ".format(pipeline_id, parser_count))
                return parser_count, parser_value
            else:
                logger.error("trigger pipeline build failed: code {} ".format(build_response.status_code))
                return None, None
        except Exception as e:
            return None, None



    def trigger_pipeline_build(self, pipeline_id, payload):
        logger.info("trigger pipeline build {} ".format(pipeline_id))
        pipeline_url = "https://dev.azure.com/mssonic/internal/_apis/pipelines/" + str(pipeline_id) + "/runs?api-version=6.0-preview.1"

        logger.debug("pipeline_url {} ".format(pipeline_url))
        # logger.debug("token {} ".format(self.token))
        logger.debug("payload {} ".format(payload))

        pipeline_build = requests.post(pipeline_url, auth=self.token, json=payload)
        if pipeline_build.status_code == requests.codes.ok:
            logger.info("trigger {} pipeline build {} OK ".format(pipeline_id, pipeline_build.json()['id']))
            return pipeline_build.json()['id']
        else:
            logger.error("ERROR!!! trigger pipeline {} build failed: code {}, payload {} ".format(pipeline_id, pipeline_build.status_code, payload))
            return None


    def get_pipeline_build_status(self, build_id):
        logger.info("get_pipeline_build_status {} ".format(build_id))
        pipeline_url = "https://dev.azure.com/mssonic/internal/_apis/build/builds/" + str(build_id) + "/timeline?api-version=5.1"
        logger.debug("pipeline_url {} ".format(pipeline_url))

        get_build_records = requests.get(pipeline_url, auth=self.token).json()

        build_complete = True
        for build_record in get_build_records["records"]:
            if build_record['state'] == "completed" :
                if build_record['result'] == "failed" :
                    logger.info("build {} failed, state {}, result {} ".format(build_id, build_record['state'], build_record['result']))
                    break

                elif build_record['result'] == "canceled":
                    logger.info("build {} canceled, state {}, result {} ".format(build_id, build_record['state'], build_record['result']))
                    break
            else :
                # logger.info("not complete ")
                build_complete = False
                continue

        return build_complete


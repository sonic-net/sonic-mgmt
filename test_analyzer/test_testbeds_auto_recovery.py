#!/bin/env python
'''testbed auto recovery
1: collect unhealthy testbeds
2: power cycle all testbeds
3: ping testbeds one by one again
4: redeploy testbed
5: sanity check
6: upload unhealthy table to Custo
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
import tempfile
import yaml

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

from test_testbeds_auto_recovery_cfg import skip_testbeds_list
from test_testbeds_auto_recovery_cfg import golden_image_url

NIGHTLY_HAWK_DIR = os.path.abspath(os.path.dirname(__file__))
SONIC_MGMT_DIR = os.path.dirname(NIGHTLY_HAWK_DIR)
ANSIBLE_DIR = os.path.join(SONIC_MGMT_DIR, 'ansible') 
NIGHTLY_PIPELINE_YML_DIR = os.path.join(SONIC_MGMT_DIR, '.azure-pipelines/nightly') 

sys.path.append(ANSIBLE_DIR)
from devutil.inv_helpers import HostManager
from devutil import conn_graph_helper
import imp

TESTBED_FILE = os.path.join(SONIC_MGMT_DIR, 'ansible/testbed.yaml') 


logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s %(filename)s:%(name)s:%(lineno)d %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DATABASE = 'SonicTestData'

g_conn_graph_facts = {}



class AUTO_RECOVERY_RC(object):
    SUCCESS = 0
    COLLECT_UNHEALTHY_TESTBED = 1
    LOCK_UNHEALTHY_TESTBED = 2
    PING_UNHEALTHY_TESTBED_1 = 3
    POWER_CYCLE_UNHEALTHY_TESTBED = 4
    PING_UNHEALTHY_TESTBED_2 = 5
    REDEPLOY_UNHEALTHY_TESTBED = 6
    SANITY_CHECK_UNHEALTHY_TESTBED = 7
    UNLOCK_UNHEALTHY_TESTBED = 8
    UPLOAD_UNHEALTHY_TESTBED_TABLE = 9 
    ERROR = 255

    @staticmethod
    def meaning(rc):
        _mapping = {
            0: 'Success',
            1: 'collect unhealthy testbeds',
            2: 'lock unhealthy testbeds',
            3: 'ping unhealthy testbeds before power cycle',
            4: 'power cycle unhealthy testbeds',
            5: 'ping unhealthy testbeds after power cycle',
            6: 'redeploy unhealthy testbeds',
            7: 'sanity check unhealthy testbeds',
            8: 'unlock unhealthy testbeds',
            9: 'upload unhealthy testbeds to CUSTO',
            255: 'Encountered error'
        }
        return _mapping[rc]



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
            | where FailedTasks contains "Run Tests" or FailedTasks contains "Upgrade Image" or FailedTasks contains "Deploy Minigraph"
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



def create_kusto_checker():
    # ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER")
    # cluster = ingest_cluster.replace('ingest-', '')
    # tenant_id = os.getenv("TEST_REPORT_AAD_TENANT_ID")
    # client_id = os.getenv("TEST_REPORT_AAD_CLIENT_ID")
    # client_key = os.getenv("TEST_REPORT_AAD_CLIENT_KEY")

    ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP")
    cluster = ingest_cluster.replace('ingest-', '')
    tenant_id = os.getenv("TEST_REPORT_AAD_TENANT_ID_BACKUP")
    client_id = os.getenv("TEST_REPORT_AAD_CLIENT_ID_BACKUP")
    client_key = os.getenv("TEST_REPORT_AAD_CLIENT_KEY_BACKUP")

    if not all([cluster, tenant_id, client_id, client_key]):
        raise RuntimeError('Could not load Kusto credentials from environment')

    return KustoChecker(cluster, tenant_id, client_id, client_key, DATABASE)


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




def create_kusto_uploader():
    # ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER")
    # cluster = ingest_cluster.replace('ingest-', '')
    # tenant_id = os.getenv("TEST_REPORT_AAD_TENANT_ID")
    # client_id = os.getenv("TEST_REPORT_AAD_CLIENT_ID")
    # client_key = os.getenv("TEST_REPORT_AAD_CLIENT_KEY")

    ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP")
    # cluster = ingest_cluster.replace('ingest-', '')
    tenant_id = os.getenv("TEST_REPORT_AAD_TENANT_ID_BACKUP")
    client_id = os.getenv("TEST_REPORT_AAD_CLIENT_ID_BACKUP")
    client_key = os.getenv("TEST_REPORT_AAD_CLIENT_KEY_BACKUP")

    if not all([ingest_cluster, tenant_id, client_id, client_key]):
        raise RuntimeError('Could not load Kusto credentials from environment')

    return KustoUploader(ingest_cluster, tenant_id, client_id, client_key, DATABASE)



def get_token(proxies):

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
        resp = requests.post(token_url, headers=headers, data=payload, proxies=proxies, timeout=10).json()
        return resp['access_token']
    except Exception as e:
        logger.error("Get token failed with exception: {}".format(repr(e)))
    return None


def get_testbed(testbed, token, proxies):
    try:
        url = 'https://tbshare.azurewebsites.net/api/testbed/{}'.format(testbed)
        headers = {
            'Authorization': 'Bearer ' + token
        }
        return requests.get(url, headers=headers, proxies=proxies, timeout=30).json()
    except:
        return {}

def lock_release_api(testbed, action, token, proxies, hours, user, reason, force, absolute):
    try:
        url = 'https://tbshare.azurewebsites.net/api/{}'.format(action)
        headers = {
            'Authorization': 'Bearer ' + token
        }
        params = {
            'name': testbed,
            'user': user,
            'force': force
        }
        if action == 'lock':
            # Extra params required only for lock
            params.update({
                'hours': hours,
                'lock_reason': reason,
                'absolute': absolute
            })

        result = requests.get(url, headers=headers, params=params, proxies=proxies, timeout=10).json()
        if 'failed' in result and result['failed']:
            logger.error('{} testbed {} failed'.format(action, testbed))
            if 'msg' in result:
                logger.info(result['msg'])
            return 2
        else:
            logger.info('{} testbed {} succeeded'.format(action, testbed))
            return 0
    except Exception as e:
        logger.error('{} testbed {} failed with exception: {}'.format(action, testbed, repr(e)))
        return 3


def add_twodim_dict(thedict, key_a, key_b, val):
    if key_a in thedict:
        thedict[key_a].update({key_b: val})
    else:
        thedict.update({key_a:{key_b: val}})

def parse_testbed(testbed_name):
    """Return a dictionary containing mapping from server name to testbeds."""
    testbed = imp.load_source('testbed', os.path.join(SONIC_MGMT_DIR, 'tests/common/testbed.py'))
    try:
        tb = testbed.TestbedInfo(TESTBED_FILE).testbed_topo[testbed_name]
    except Exception:
        logger.info("{} doesn't exist in {} file.".format(testbed_name, TESTBED_FILE))
        return
    return tb

def get_conn_graph_facts(hosts):
    global g_conn_graph_facts
    g_conn_graph_facts = {}
    hostnames = hosts.keys()
    g_conn_graph_facts = conn_graph_helper.get_conn_graph_facts(hostnames)
    return g_conn_graph_facts

def get_console_info(hostname, attrs):
    console_info = get_console_info_from_conn_graph(hostname)
    if not console_info:
        console_info = get_console_info_from_inventory(attrs)
    if not console_info:
        logger.info("Failed to get console info for {}".format(hostname))
    return console_info

def get_console_info_from_conn_graph(hostname):
    """
    Read console info from conn_graph_facts.
    """
    console_info = {}
    if hostname in g_conn_graph_facts['device_console_info'] and g_conn_graph_facts['device_console_info'][hostname]:
        console_info['console_type'] = g_conn_graph_facts['device_console_info'][hostname]['Protocol']
        console_info['console_host'] = g_conn_graph_facts['device_console_info'][hostname]['ManagementIp']
        console_info['console_port'] = g_conn_graph_facts['device_console_link'][hostname]['ConsolePort']['peerport']
    return console_info

def get_console_info_from_inventory(attrs):
    """
    Read console info from inventory file. This should be a fallback of get_console_info_from_conn_graph.
    """
    console_info = {}
    keys = ['console_type', 'console_host', 'console_port']
    for k in keys:
        if k in attrs:
            console_info[k] = attrs[k]
    return console_info

def get_testbed_info(testbed):
    tbinfo = parse_testbed(testbed)
    if tbinfo is None:
        logger.error("Can't find information for testbed {}, please verify if testbed name is correct.".format(testbed))
        return None, None, None

    hostmgr = HostManager(os.path.join(ANSIBLE_DIR, tbinfo['inv_name']))
    dut_console = []
    dut_ip = []
    for dut in tbinfo['duts']:
        # logger.info("testbed {} DUT {} {} ".format(testbed, type(dut), dut))
        hosts = hostmgr.get_host_list('all', dut)
        if not hosts:
            logger.error('testbed {} dut {} No matching hosts'.format(testbed, dut))
            raise RuntimeError('Can not find DUT {} information for testbed {} '.format(dut, testbed))
        # logger.info("testbed {} DUT {} hosts {} ".format(testbed, dut, hosts))
        get_conn_graph_facts(hosts)
        get_info = False
        for hostname, vars in hosts.items():
            console_info = get_console_info(hostname, vars)
            if not console_info:
                continue
            if console_info['console_type'] == 'ssh':
                dut_console.append('ssh ' + vars['creds']['username'] + ':p=' + console_info['console_port'] + '@' + console_info['console_host'])
            else:
                dut_console.append(console_info['console_type'] + ' ' + console_info['console_host'] + ' ' + console_info['console_port'])
            get_info = True
        if get_info == False:
            dut_console.append(None)

        get_info = False
        for _, vars in hosts.items():
            dut_ip.append(vars['ansible_host'])
            get_info = True
        if get_info == False:
            dut_ip.append(None)

    return tbinfo['duts'], dut_console, dut_ip


def get_Pipeline_ImageUrl():
    pipeline_image_url = {}
    for home, dirs, files in os.walk(NIGHTLY_PIPELINE_YML_DIR):
        for file in files:
            if file.endswith('.yml') and file.startswith('vms'):
                # logger.info("file {} ".format(os.path.join(home, file)))
                testbed_name, branch_name, image_url = parser_YmlFile(os.path.join(home, file))
                if "202012" in branch_name:
                    pipeline_image_url[testbed_name] = image_url
    return pipeline_image_url


def parser_YmlFile(fileName):
    with open(fileName) as f:
        my_dict = yaml.safe_load(f)
        # logger.info("my_dict {} ".format(my_dict))
        # for key,value in my_dict.items():
        #     logger.info("{} : {} {}".format(key, value, type(value)))
        
        testbed_name = None
        image_url = None
        branch_name = None
        for para in my_dict['parameters']:
            if para['name'] == 'TESTBED_NAME':
                # logger.info("{}".format(para['default']))
                testbed_name = para['default']
            if para['name'] == 'IMAGE_URL':
                # logger.info("{}".format(para['default']))
                image_url = para['default']   

        if len(my_dict['schedules']) > 1 or len(my_dict['schedules'][0]['branches']['include']) > 1:
            logger.info("schedules ERROR {}".format(my_dict['schedules']))
            raise RuntimeError('schedules ERROR {} '.format(my_dict['schedules']))

        branch_name = my_dict['schedules'][0]['branches']['include'][0]

        if testbed_name == None or image_url == None or branch_name == None:
            raise RuntimeError('get information ERROR {} {} {} '.format(testbed_name, image_url, branch_name))

        # logger.info('get information {} {} {} '.format(testbed_name, image_url, branch_name))
        # upgradeImageUrl[testbed_name + '_' + branch_name] = {'testbed_name' : testbed_name,  'branch' : branch_name, 'image_url' : image_url}
        return testbed_name, branch_name, image_url


class Testbeds_auto_recovery(object):
    def __init__(self, verbose = False, debug_mode = False, sanity_check = False, golden_image = False, agent_pool = 'nightly'):
        self.verbose = verbose
        self.debug_mode = debug_mode
        self.sanity_check = sanity_check
        self.agent_pool = agent_pool
        self.unhealthy_testbeds_count = 0
        self.unhealthy_testbeds = {}
        self.unhealthy_testbeds_ToCusto = {}
        self.autoRecovery_table = {}
        self.need_powercycle_testbeds = []
        self.build_testbeds_list = []
        self.lock_hours = 2
        self.lock_user = "NIGHTLY_HAWK"
        self.lock_reason = "testbed unhealthy, try to auto recovery"
        self.current_step = AUTO_RECOVERY_RC.SUCCESS
        self.collect_unhealthy_table_age = '24h'
        self.collect_autoRecovery_table_age = '24h'
        self.kusto_checker = None
        self.kusto_uploader = None
        self.proxies = {'http': os.environ.get('http_proxy'), 'https': os.environ.get('http_proxy')}
        self.token = get_token(self.proxies)
        self.max_build_count = 3
        self.trigger_redeploy_id = 680
        self.trigger_sanitycheck_id = 682
        # self.abort = False
        self.start_time = None
        self.total_timeout = 60 * 60 * 3   # pipeline timeout is 3 hours
        self.redeploy_timeout = 60 * 45    # redeploy timeout + sanity timeout < 2 hours
        self.sanity_timeout = 60 * 65
        self.current_loop = 0
        self.testbedName = None
        if golden_image:
            self.upgradeImageUrl = golden_image_url
        else:
            self.upgradeImageUrl = get_Pipeline_ImageUrl()

    def parser_unhealthy_testbeds(self):
        self.current_step = AUTO_RECOVERY_RC.COLLECT_UNHEALTHY_TESTBED
        logger.info("parser input testbeds {}".format(self.testbedName))
        testbedName_list = self.testbedName.split(",")

        for testbedTmp in testbedName_list:
            testbed = testbedTmp.strip()

            if (self.agent_pool == 'nightly-bjw' and '-bjw-' not in testbed) \
                or (self.agent_pool == 'nightly-svc' and 'svc' not in testbed) \
                or (self.agent_pool == 'nightly' and (('-bjw-' in testbed) or ('svc' in testbed))):

                logger.error("testbed {} agent pool {} mismatch ".format(testbed, self.agent_pool))
                continue

            # get testbed's DUT, IP, console
            dut, console, ip = get_testbed_info(testbed)
            if dut == None and console == None and ip == None:
                logger.error("ERROR cannot get the information of testbed {} ".format(testbed))
                continue

            self.unhealthy_testbeds[testbed] = {'UTCTimestamp'  : str(datetime.datetime.utcnow()),
                                                'TestbedName'   : testbed,
                                                'DutName'       : dut,
                                                'DutIP'         : ip,
                                                'Console'       : console,
                                                'Powercycle'    : 'No',
                                                'buildID'       : {"redeploy" : None, "sanity" : None},
                                                'Priority'      : 0}

        if self.verbose :
            logger.info("unhealthy_testbeds {} ".format(self.unhealthy_testbeds)) 
     
        self.unhealthy_testbeds_count = len(self.unhealthy_testbeds.keys())
        logger.info("collect {} unhealthy_testbeds {} ".format(self.unhealthy_testbeds_count, self.unhealthy_testbeds.keys()))

        self.check_unhealthy_testbeds()
        return 


    def collect_unhealthy_testbeds(self):
        self.current_step = AUTO_RECOVERY_RC.COLLECT_UNHEALTHY_TESTBED
        logger.info("collect unhealthy testbeds ")

        # query unhealthy testbeds table, nightly pipeline build failed table
        self.kusto_checker = create_kusto_checker()
        currentUnhealthyTable = self.kusto_checker.query_unhealthy_testbeds(self.collect_unhealthy_table_age)
        if self.verbose :
            logger.info("get currentUnhealthyTable {} ".format(currentUnhealthyTable))

        testbedName_list = []
        unhealthy_testbeds_table = {}
        for row in currentUnhealthyTable.primary_results[0].rows:
            if row['TestbedName'] not in testbedName_list :
                testbedName_list.append(row['TestbedName'])     
                unhealthy_testbeds_table[row['TestbedName']] = {'UTCTimestamp' : str(row['StartTimestamp']),
                                                                'TestbedName'  : row['TestbedName']}

        if self.verbose :
            logger.info("query {} unhealthy testbeds".format(len(unhealthy_testbeds_table.keys())))
            for testbed in unhealthy_testbeds_table.keys():
                logger.info("unhealthy testbeds: {} ".format(unhealthy_testbeds_table[testbed]))


        # query autoRecovery table, find out testbeds which have not completed auto recover sequence 
        if self.kusto_checker == None:
            self.kusto_checker = create_kusto_checker()
        currentAutoRecoveryTable = self.kusto_checker.query_autoRecovery_testbeds(self.collect_autoRecovery_table_age)
        if self.verbose :
            logger.info("get currentAutoRecoveryTable {} ".format(currentAutoRecoveryTable))

        # collect auto recovery table's testbeds, select latest one if same testbed
        autoRecovery_testbeds_list = []
        autoRecovery_testbeds = {}
        for row in currentAutoRecoveryTable.primary_results[0].rows: 
            if row['TestbedName'] not in autoRecovery_testbeds_list:
                autoRecovery_testbeds[row['TestbedName']] = {'UTCTimestamp' :  str(row['UTCTimestamp']), 'TestbedName' : row['TestbedName'], 'Priority' : row['Priority'], 'DutName' : row['DutName'], 'DutIP' : row['DutIP'], 'Console' : row['Console']}
                autoRecovery_testbeds_list.append(row['TestbedName'])
                if self.verbose :
                    logger.info("add Testbed  {} into list, timestamp {} priority {} ".format(row['TestbedName'], str(row['UTCTimestamp']), row['Priority']))
            else:
                if str(row['UTCTimestamp']) > str(autoRecovery_testbeds[row['TestbedName']]['UTCTimestamp']):
                    autoRecovery_testbeds.update({row['TestbedName'] : {'UTCTimestamp' :  str(row['UTCTimestamp']), 'TestbedName' : row['TestbedName'], 'Priority' : row['Priority'], 'DutName' : row['DutName'], 'DutIP' : row['DutIP'], 'Console' : row['Console']}})
                    if self.verbose :
                        logger.info("update Testbed {} into list, timestamp {} priority {} ".format(row['TestbedName'], str(row['UTCTimestamp']), row['Priority']))
        if self.verbose :
            for key, value in autoRecovery_testbeds.items():
                logger.info("autoRecovery_testbeds {} : {} ".format(key, value)) 
    
            logger.info("autoRecovery_testbeds_list {} ".format(autoRecovery_testbeds_list)) 

        # move testbeds which priority is not 0 to unhealthy testbeds dict
        for testbed in autoRecovery_testbeds_list[:]:
            if autoRecovery_testbeds[testbed]['Priority'] != 0:
                if (self.agent_pool == 'nightly-bjw' and '-bjw-' not in testbed) \
                    or (self.agent_pool == 'nightly-svc' and 'svc' not in testbed) \
                    or (self.agent_pool == 'nightly' and (('-bjw-' in testbed) or ('svc' in testbed))):

                    logger.error("testbed {} agent pool {} mismatch ".format(testbed, self.agent_pool))
                    continue

                # get testbed's DUT, IP, console
                dut, console, ip = get_testbed_info(testbed)
                if dut == None and console == None and ip == None:
                    logger.error("ERROR cannot get the information of testbed {} ".format(testbed))
                    continue

                autoRecovery_testbeds_list.remove(testbed)

                self.unhealthy_testbeds[testbed] = {'UTCTimestamp'  : autoRecovery_testbeds[testbed]['UTCTimestamp'],
                                                    'TestbedName'   : autoRecovery_testbeds[testbed]['TestbedName'],
                                                    'DutName'       : dut,
                                                    'DutIP'         : ip,
                                                    'Console'       : console,
                                                    'Powercycle'    : 'No',
                                                    'buildID'       : {"redeploy" : None, "sanity" : None},
                                                    'Priority'      : autoRecovery_testbeds[testbed]['Priority']}

                # self.unhealthy_testbeds[testbed] = {'UTCTimestamp'  : autoRecovery_testbeds[testbed]['UTCTimestamp'],
                #                                     'TestbedName'   : autoRecovery_testbeds[testbed]['TestbedName'],
                #                                     'DutName'       : autoRecovery_testbeds[testbed]['DutName'],
                #                                     'DutIP'         : autoRecovery_testbeds[testbed]['DutIP'],
                #                                     'Console'       : autoRecovery_testbeds[testbed]['Console'],
                #                                     'Powercycle'    : 'No',
                #                                     'buildID'       : {"redeploy" : None, "sanity" : None},
                #                                     'Priority'      : autoRecovery_testbeds[testbed]['Priority']}

        if self.verbose :
            logger.info("autoRecovery_testbeds_list {} ".format(autoRecovery_testbeds_list))

        # move testbeds which in unhealthy table into unhealthy testbeds dict, 
        for testbed in unhealthy_testbeds_table.keys() :
            # skip testbed which in skip list
            found_skip = False
            for skip_testbed in skip_testbeds_list:
                if isinstance(skip_testbed, str):
                    if skip_testbed in testbed:
                        logger.info("skip testbed parttern {}, skip testbed {}".format(skip_testbed, testbed))
                        found_skip = True
                        break
            if found_skip:
                continue

            # ignore the one which already in auto recovery table and priority is 0
            if testbed not in autoRecovery_testbeds_list and testbed not in self.unhealthy_testbeds.keys():

                if (self.agent_pool == 'nightly-bjw' and '-bjw-' not in testbed) \
                    or (self.agent_pool == 'nightly-svc' and 'svc' not in testbed) \
                    or (self.agent_pool == 'nightly' and (('-bjw-' in testbed) or ('svc' in testbed))):

                    logger.error("testbed {} agent pool {} mismatch ".format(testbed, self.agent_pool))
                    continue

                # get testbed's DUT, IP, console
                dut, console, ip = get_testbed_info(testbed)
                if dut == None and console == None and ip == None:
                    logger.error("ERROR cannot get the information of testbed {} ".format(testbed))
                    continue



                self.unhealthy_testbeds[testbed] = {'UTCTimestamp'  : unhealthy_testbeds_table[testbed]['UTCTimestamp'],
                                                    'TestbedName'   : unhealthy_testbeds_table[testbed]['TestbedName'],
                                                    'DutName'       : dut,
                                                    'DutIP'         : ip,
                                                    'Console'       : console,
                                                    'Powercycle'    : 'No',
                                                    'buildID'       : {"redeploy" : None, "sanity" : None},
                                                    'Priority'      : 0}        

        self.unhealthy_testbeds_count = len(self.unhealthy_testbeds.keys())
        logger.info("collect {} unhealthy_testbeds {} ".format(self.unhealthy_testbeds_count, self.unhealthy_testbeds.keys()))

        self.check_unhealthy_testbeds()
        return 


    def lock_unhealthy_testbeds(self):
        self.current_step = AUTO_RECOVERY_RC.LOCK_UNHEALTHY_TESTBED
        logger.info("lock unhealthy testbeds ")  

        if len(self.unhealthy_testbeds.keys()) == 0 :
            logger.info("unhealthy_testbeds is empty, no need to deploy ") 
            return

        if len(self.build_testbeds_list) != 0:
            raise RuntimeError('current build testbeds list is not empty {}'.format(self.build_testbeds_list))

        self.build_testbeds_list.clear()
        build_count = 0
        unhealthy_testbeds_list = sorted(self.unhealthy_testbeds, key=lambda x:int(self.unhealthy_testbeds[x]['Priority']), reverse=True)
        for testbed in unhealthy_testbeds_list[:] :
            if build_count < self.max_build_count :
                rst, lock_statue = self.lock_release_testbed(testbed, "lock")
                if rst == True:
                    build_count = build_count + 1 
                    if self.verbose :
                        logger.info("testbed {} priority {} add into build list".format(testbed, self.unhealthy_testbeds[testbed]['Priority']))
                    self.build_testbeds_list.append(testbed)
                else :
                    logger.info("{} testbed {} failed, status {}, prio {} {} ".format("lock", testbed, lock_statue, type(self.unhealthy_testbeds[testbed]['Priority']), self.unhealthy_testbeds[testbed]['Priority']))
                    self.update_testbeds_ToCusto(testbed, False, None, None, None, None, "Lock failure", self.unhealthy_testbeds[testbed]['Priority'] + 1, lock_statue["lock"])
                    del self.unhealthy_testbeds[testbed]
            else :
                break

        logger.info("locked testbeds: {} ".format(self.build_testbeds_list))
        self.check_unhealthy_testbeds()
        return


    def ping_unhealthy_testbeds(self):
        self.current_step = AUTO_RECOVERY_RC.PING_UNHEALTHY_TESTBED_1
        logger.info("ping unhealthy testbeds {} before power cycle".format(self.build_testbeds_list))  

        for testbed in self.build_testbeds_list :
            if self.verbose :
                logger.info("ping testbed {} ".format(testbed, self.unhealthy_testbeds[testbed]['DutIP']))

            for ip in self.unhealthy_testbeds[testbed]['DutIP']:
                response = os.system("ping -c 2 " + ip)
                if response != 0:
                    self.need_powercycle_testbeds.append(testbed)
                    self.unhealthy_testbeds[testbed].update({'Powercycle' : "Yes"})
                    break

        if (len(self.need_powercycle_testbeds) > 0):
            logger.info("unreachable, need to power cycle testbed: {} ".format(self.need_powercycle_testbeds)) 
   
        return


    def powercycle_unhealthy_testbeds(self):
        self.current_step = AUTO_RECOVERY_RC.POWER_CYCLE_UNHEALTHY_TESTBED
        logger.info("power cycle unreachable testbeds ")  

        if (len(self.need_powercycle_testbeds) == 0) or (len(self.build_testbeds_list) == 0) :
            logger.info("no testbeds need to power cycle ") 
            return

        for testbed in self.build_testbeds_list:
            if testbed in self.need_powercycle_testbeds :
                for DutName in self.unhealthy_testbeds[testbed]['DutName']: 
                    # python2 ./../ansible/devutils -i ./../ansible/str -a pdu_on -l str-sn3800-01
                    # cmd_line = "python2 ./../ansible/devutils -i ./../ansible/" + self.unhealthy_testbeds[testbed]['DutName'].split("-", 1)[0] + " -a pdu_off -l " + self.unhealthy_testbeds[testbed]['DutName']
                    inventory = DutName.split("-", 1)[0]
                    if 'svc' in inventory:
                        inventory = 'strsvc'

                    cmd_line = "python2 ./../ansible/devutils -i ./../ansible/" + inventory + " -a pdu_off -l " + DutName
                    if self.verbose :
                        logger.info("power off {} CMD: {}".format(self.unhealthy_testbeds[testbed]['TestbedName'], cmd_line))
                    if not self.debug_mode :
                        os.system(cmd_line)
        if not self.debug_mode :
            time.sleep(30)

        for testbed in self.build_testbeds_list:
            if testbed in self.need_powercycle_testbeds :
                for DutName in self.unhealthy_testbeds[testbed]['DutName']: 
                    # cmd_line = "python2 ./../ansible/devutils -i ./../ansible/" + self.unhealthy_testbeds[testbed]['DutName'].split("-", 1)[0] + " -a pdu_on -l " + self.unhealthy_testbeds[testbed]['DutName']
                    inventory = DutName.split("-", 1)[0]
                    if 'svc' in inventory:
                        inventory = 'strsvc'

                    cmd_line = "python2 ./../ansible/devutils -i ./../ansible/" + inventory + " -a pdu_on -l " + DutName
                    if self.verbose :
                        logger.info("power on  {} CMD: {}".format(self.unhealthy_testbeds[testbed]['TestbedName'], cmd_line))
                    if not self.debug_mode :
                        os.system(cmd_line)
        if not self.debug_mode :
            time.sleep(180)
        return 


    def ping_unhealthy_testbeds_after_powercycle(self):
        self.current_step = AUTO_RECOVERY_RC.PING_UNHEALTHY_TESTBED_2
        logger.info("ping unhealthy testbeds after power cycle")   

        for testbed in self.build_testbeds_list[:]:
            if testbed in self.need_powercycle_testbeds :
                if self.verbose :
                    logger.info("ping testbed {} after power cycle ".format(testbed))

                for ip in self.unhealthy_testbeds[testbed]['DutIP']:
                    # response = os.system("ping -c 2 " + self.unhealthy_testbeds[testbed]['DutIP'])
                    response = os.system("ping -c 2 " + ip)
                    if response != 0:
                        logger.info("move ping failed testbed {} to custo table".format(testbed))

                        self.lock_release_testbed(testbed, "release")
                        self.update_testbeds_ToCusto(testbed, True, False, self.unhealthy_testbeds[testbed]['Powercycle'], None, None, "success", 0, "unreachable after power cycle")
                        del self.unhealthy_testbeds[testbed]
                        self.build_testbeds_list.remove(testbed)
                        break

        self.check_unhealthy_testbeds()
        return


    def redeploy_unhealthy_testbeds(self):
        self.current_step = AUTO_RECOVERY_RC.REDEPLOY_UNHEALTHY_TESTBED
        logger.info("redeploy unhealthy testbeds {} ".format(self.unhealthy_testbeds.keys())) 

        if len(self.build_testbeds_list) == 0 :
            logger.info("unhealthy_testbeds is empty, no need to deploy this time") 
            return

        TOKEN = os.environ.get('AZURE_DEVOPS_MSSONIC_TOKEN')
        if not TOKEN:
            logger.error("Get token failed, Must export environment variable AZURE_DEVOPS_MSSONIC_TOKEN")
            if self.verbose :
                logger.error("No token, move all testbeds {} to custo table".format(self.unhealthy_testbeds.keys()))

            for testbed in self.unhealthy_testbeds.copy() :
                if testbed in self.build_testbeds_list:
                    self.lock_release_testbed(testbed, "release")
                self.update_testbeds_ToCusto(testbed, True, True, self.unhealthy_testbeds[testbed]['Powercycle'], "no token", None, "success", self.unhealthy_testbeds[testbed]['Priority'] + 1, "redeploy get token failed, no AZURE_DEVOPS_MSSONIC_TOKEN")
                del self.unhealthy_testbeds[testbed]
            self.build_testbeds_list.clear()
            return
        AUTH = ('', TOKEN)

      
        time_check = time.time()
        if (time_check - self.start_time) > (self.total_timeout - self.redeploy_timeout):
            logger.info("deploy: start time {} eplase time {} remain testbeds {} ".format(self.start_time, time_check - self.start_time, self.unhealthy_testbeds.keys()))

            for testbed in self.unhealthy_testbeds.copy() :
                if testbed in self.build_testbeds_list:
                    self.lock_release_testbed(testbed, "release")
                self.update_testbeds_ToCusto(testbed, False, True, self.unhealthy_testbeds[testbed]['Powercycle'], "skip", None, "success", self.unhealthy_testbeds[testbed]['Priority'] + 1, "reach to timeout, skip redeploy build")
                del self.unhealthy_testbeds[testbed]
            self.build_testbeds_list.clear()
            return

        if self.debug_mode:
            self.trigger_redeploy_id = 570
            self.redeploy_timeout = 60 * 5

        logger.info("start to redeploy unhealthy testbeds {} ".format(self.build_testbeds_list))
        self.trigger_build_pipelines(AUTH, self.trigger_redeploy_id)
        self.check_unhealthy_testbeds()

        logger.info("wait build pipeline done {} ".format(self.build_testbeds_list))
        self.wait_pipelines_done(AUTH,  int(self.redeploy_timeout / (60/3)), self.redeploy_timeout)
        self.check_unhealthy_testbeds()

        return

    def sanity_unhealthy_testbeds(self):
        self.current_step = AUTO_RECOVERY_RC.SANITY_CHECK_UNHEALTHY_TESTBED
        logger.info("sanity check unhealthy testbeds {} ".format(self.unhealthy_testbeds.keys())) 

        if not self.sanity_check:
            logger.warning("skip to do sanity check ") 
            return

        if len(self.build_testbeds_list) == 0 :
            logger.info("current build_testbeds_list is empty, no need to sanity check ") 
            return

        TOKEN = os.environ.get('AZURE_DEVOPS_MSSONIC_TOKEN')
        if not TOKEN:
            logger.error("Get token failed, Must export environment variable AZURE_DEVOPS_MSSONIC_TOKEN")
            if self.verbose :
                logger.error("No token, move all testbeds {} to custo table".format(testbed))

            for testbed in self.unhealthy_testbeds.copy() :
                if testbed in self.build_testbeds_list[:] :
                    self.lock_release_testbed(testbed, "release")
                self.update_testbeds_ToCusto(testbed, True, True, self.unhealthy_testbeds[testbed]['Powercycle'], "no token", None, "success", self.unhealthy_testbeds[testbed]['Priority'] + 1, "sanity check get token failed, Must export environment variable AZURE_DEVOPS_MSSONIC_TOKEN")
                del self.unhealthy_testbeds[testbed]
            self.build_testbeds_list.clear()
            return
        AUTH = ('', TOKEN)

        time_check = time.time()
        if (time_check - self.start_time) > (self.total_timeout - self.sanity_timeout):
            logger.info("sanity check: start time {} eplase time {} remain testbeds {} ".format(self.start_time, time_check - self.start_time, self.unhealthy_testbeds.keys()))

            for testbed in self.unhealthy_testbeds.copy() :
                if testbed in self.build_testbeds_list:
                    self.lock_release_testbed(testbed, "release")
                self.update_testbeds_ToCusto(testbed, False, True, self.unhealthy_testbeds[testbed]['Powercycle'], 
                                            "success#" + str(self.unhealthy_testbeds[testbed]['buildID']['redeploy']), 
                                            'skip', "success", self.unhealthy_testbeds[testbed]['Priority'] + 1, "reach to timeout, skip sanity check")
                del self.unhealthy_testbeds[testbed]
            self.build_testbeds_list.clear()
            return

        if self.debug_mode:
            self.trigger_sanitycheck_id = 660
            self.sanity_timeout = 60 * 5

        # fixme try to wait testbeds stable before pretest (after redeploy)
        if not self.debug_mode :
            time.sleep(30)
        logger.info("start to sanity check unhealthy testbeds {} ".format(self.unhealthy_testbeds.keys()))
        self.trigger_build_pipelines(AUTH, self.trigger_sanitycheck_id)
        self.check_unhealthy_testbeds()

        logger.info("wait build pipeline done {} ".format(self.build_testbeds_list))
        self.wait_pipelines_done(AUTH, int(self.sanity_timeout / (60/3)), self.sanity_timeout)
        self.check_unhealthy_testbeds()

        return


    def unlock_unhealthy_testbeds(self):
        self.current_step = AUTO_RECOVERY_RC.UNLOCK_UNHEALTHY_TESTBED
        logger.info("unlock unhealthy testbeds {} ".format(self.unhealthy_testbeds.keys())) 

        if len(self.build_testbeds_list) == 0 :
            logger.info("current build_testbeds_list is empty, no need to unlock testbeds ") 
            return

        # for testbed in self.unhealthy_testbeds.copy() :
        for testbed in self.build_testbeds_list[:]:
            rst, lock_statue = self.lock_release_testbed(testbed, "release")
            if rst == True:
                if self.verbose :
                    logger.info("{} testbed {} successed ".format("release", testbed))
                self.update_testbeds_ToCusto(testbed, False, True, self.unhealthy_testbeds[testbed]['Powercycle'], \
                                            "success#" + str(self.unhealthy_testbeds[testbed]['buildID']['redeploy']), \
                                            "success#" + str(self.unhealthy_testbeds[testbed]['buildID']['sanity']), \
                                            "success", 0, "auto recover complete")
            else :
                logger.info("{} testbed {} failed, status {} ".format("release", testbed, lock_statue))
                self.update_testbeds_ToCusto(testbed, False, True, self.unhealthy_testbeds[testbed]['Powercycle'], \
                                            "success#" + str(self.unhealthy_testbeds[testbed]['buildID']['redeploy']), \
                                            "success#" + str(self.unhealthy_testbeds[testbed]['buildID']['sanity']), \
                                             "UnLock failure", 0, "auto recover complete")

            del self.unhealthy_testbeds[testbed]
            self.build_testbeds_list.remove(testbed)

        self.check_unhealthy_testbeds()
        return 


    def upload_unhealthy_testbeds_to_custo(self):
        self.current_step = AUTO_RECOVERY_RC.UPLOAD_UNHEALTHY_TESTBED_TABLE
        logger.info("upload table to custo {} ".format(self.unhealthy_testbeds_ToCusto)) 

        custo_table_data = []
        for testbed in self.unhealthy_testbeds_ToCusto.keys() :
            if self.verbose :
                logger.info("upload testbed {} to custo, {} ".format(testbed, self.unhealthy_testbeds_ToCusto[testbed]))

            self.unhealthy_testbeds_ToCusto[testbed]['UTCTimestamp'] = str(datetime.datetime.utcnow())

            custo_table_data.append(self.unhealthy_testbeds_ToCusto[testbed])

        logger.info("upload to custo {}".format(custo_table_data))

        self.kusto_uploader = create_kusto_uploader()

        props = IngestionProperties(
            database=DATABASE,
            table="TestbedAutoRecoveryData",
            data_format=DataFormat.JSON,
            ingestion_mapping_reference="TestbedAutoRecoveryDataMapping"
        )

        with tempfile.NamedTemporaryFile(mode="w+") as temp:
            if isinstance(custo_table_data, list):
                temp.writelines('\n'.join([json.dumps(entry) for entry in custo_table_data]))
            else:
                temp.write(json.dumps(custo_table_data))
            temp.seek(0)

            if self.kusto_uploader.ingestion_client:
                logger.info("Ingest to backup cluster...")
                self.kusto_uploader.ingestion_client.ingest_from_file(temp.name, ingestion_properties=props)                

        return


    def lock_release_testbed(self, testbed, lock_release):
        lock_release_statue = {}
        if self.token == None :
            lock_release_statue[lock_release] = "get token failed"
            return False, lock_release_statue

        if self.verbose :
            logger.info("{} testbed {} ".format(lock_release, testbed))

        testbed_lock = {}
        for count in range(5):
            testbed_lock = get_testbed(testbed, self.token, self.proxies)
            if testbed_lock:
                if testbed_lock.get('failed') == False:
                    break
            time.sleep(1)
            logger.info("testbed {} get_testbed failed, try {} ".format(testbed, count + 1))

        logger.info("testbed {} {}".format(testbed, testbed_lock))
        if testbed_lock:
            if testbed_lock.get('failed', True):
                logger.error('Failed to get testbed {} details {}'.format(testbed, testbed_lock))
                lock_release_statue[lock_release] = "get testbed info failed"
                return False, lock_release_statue

        lock_statue = None
        if lock_release == "lock" :
            if ((len(testbed_lock['testbed']['locked_by']) == 0 
                    and len(testbed_lock['testbed']['lock_time']) == 0 
                    and len(testbed_lock['testbed']['release_time']) == 0) 
                or testbed_lock['testbed']['locked_by'] == self.lock_user) :

                lock_statue = lock_release_api(testbed, lock_release, self.token, self.proxies, self.lock_hours, self.lock_user, self.lock_reason, 'false', 'true')
        else :
            if (testbed_lock['testbed']['locked_by']) == self.lock_user :
                lock_statue = lock_release_api(testbed, lock_release, self.token, self.proxies, None, self.lock_user, None, 'true', 'false')


        if lock_statue == None :
            logger.error("{} testbed {} skip, locked by {} [{} ~ {}]".format(lock_release, testbed, testbed_lock['testbed']['locked_by'], testbed_lock['testbed']['lock_time'], testbed_lock['testbed']['release_time']))
            lock_release_statue[lock_release] = "locked by {} [{} ~ {}]".format(testbed_lock['testbed']['locked_by'], testbed_lock['testbed']['lock_time'], testbed_lock['testbed']['release_time'])
            return False, lock_release_statue
        elif lock_statue == 0 :
            if self.verbose :
                logger.info("{} testbed {} succeeded".format(lock_release, testbed))
            lock_release_statue[lock_release] = "successed"
            return True, lock_release_statue
        else :
            logger.error("{} testbed {} failed, lock_statue {}".format(lock_release, testbed, lock_statue))
            lock_release_statue[lock_release] = "API return failed"
            return False, lock_release_statue

        return


    def trigger_build_pipelines(self, auth, pipeline_id):
        logger.info("trigger pipeline build {} ".format(pipeline_id))

        pipeline_url = "https://dev.azure.com/mssonic/internal/_apis/pipelines/" + str(pipeline_id) + "/runs?api-version=6.0-preview.1"

        # for testbed in self.unhealthy_testbeds.copy() :
        for testbed in self.build_testbeds_list[:]:
            if self.verbose :
                logger.info("trigger testbed {} build {} start ".format(testbed, pipeline_id))

            if self.agent_pool != 'nightly' and self.agent_pool != 'nightly-bjw' and self.agent_pool != 'nightly-svc' :
                raise RuntimeError('agent pool {} ERROR!!! testbed {} pipeline_id {} '.format(self.agent_pool, testbed, pipeline_id))
                return

            if pipeline_id == self.trigger_redeploy_id:
                for DutName in self.unhealthy_testbeds[testbed]['DutName']:
                    # cmd_line = "python2 ./../ansible/devutils -i ./../ansible/" + self.unhealthy_testbeds[testbed]['DutName'][0].split("-", 1)[0] + " -a run --cmd 'show version' -l " + self.unhealthy_testbeds[testbed]['DutName']
                    inventory = DutName.split("-", 1)[0]
                    if 'svc' in inventory:
                        inventory = 'strsvc'
                    cmd_line = "python2 ./../ansible/devutils -i ./../ansible/" + inventory + " -a run --cmd 'show version' -l " + DutName
                    if self.verbose :
                        logger.info("testbeds {} show version CMD: {}".format(self.unhealthy_testbeds[testbed]['TestbedName'], cmd_line))
                    os.system(cmd_line)

                payload = {
                    "templateParameters" : {
                        "TESTBED_NAME" : self.unhealthy_testbeds[testbed]['TestbedName'] ,
                        "RUN_STOP_TOPO_VMS" : 'false',
                        "RUN_START_TOPO_VMS" : 'false',
                        "AGENT_POOL" : self.agent_pool
                    }
                }
            elif pipeline_id == self.trigger_sanitycheck_id:
                image_url = None
                if testbed in self.upgradeImageUrl.keys():
                    image_url = self.upgradeImageUrl[testbed]

                if image_url != None:
                    logger.info("testbed {} upgrade image url {} agent_pool {} ".format(testbed, image_url, self.agent_pool))
                    payload = {
                        "templateParameters" : {
                            "TESTBED_NAME" : self.unhealthy_testbeds[testbed]['TestbedName'] ,
                            "IMAGE_URL" : image_url,
                            "AGENT_POOL" : self.agent_pool
                        }
                    }
                else:
                    logger.warning("WARNING testbed {} upgrade image url is None, agent_pool {} ".format(testbed, self.agent_pool))
                    payload = {
                        "templateParameters" : {
                            "TESTBED_NAME" : self.unhealthy_testbeds[testbed]['TestbedName'] ,
                            "AGENT_POOL" : self.agent_pool
                        }
                    }
            else:
                raise RuntimeError('pipeline_id {} incorrect, corrent ID redeploy {} sanity {}'.format(pipeline_id, self.trigger_redeploy_id, self.trigger_sanitycheck_id))
                return

            build_testbed = requests.post(pipeline_url, auth=auth, json=payload)
            if build_testbed.status_code == requests.codes.ok:
                if pipeline_id == self.trigger_redeploy_id:
                    self.unhealthy_testbeds[testbed]['buildID'].update({"redeploy" : build_testbed.json()['id']})
                elif pipeline_id == self.trigger_sanitycheck_id:
                    self.unhealthy_testbeds[testbed]['buildID'].update({"sanity" : build_testbed.json()['id']})
                else:
                    raise RuntimeError('pipeline_id {} incorrect, corrent ID redeploy {} sanity {}'.format(pipeline_id, self.trigger_redeploy_id, self.trigger_sanitycheck_id))
   
                if self.verbose :
                    logger.info("testbed {} trigger {} pipeline build {} OK ".format(testbed, pipeline_id, self.unhealthy_testbeds[testbed]['buildID']))
            else:
                logger.error("testbed testbed {} trigger pipeline build failed: code {} {} ".format(testbed, build_testbed.status_code, build_testbed.json()))

                if pipeline_id == self.trigger_redeploy_id:
                    self.update_testbeds_ToCusto(testbed, True, True, self.unhealthy_testbeds[testbed]['Powercycle'], 
                                                    "trigger failed", None, "success", self.unhealthy_testbeds[testbed]['Priority'] + 1, "trigger pipeline build failed: code " + str(build_testbed.status_code))
                elif pipeline_id == self.trigger_sanitycheck_id:
                    self.update_testbeds_ToCusto(testbed, True, True, self.unhealthy_testbeds[testbed]['Powercycle'], 
                                                    "success#" + str(self.unhealthy_testbeds[testbed]['buildID']["redeploy"]), 
                                                    "trigger failed", "success", 0, "trigger pipeline build failed: code " + str(build_testbed.status_code))
                else:
                    raise RuntimeError('pipeline_id {} incorrect, corrent ID redeploy {} sanity {}'.format(pipeline_id, self.trigger_redeploy_id, self.trigger_sanitycheck_id))


                self.lock_release_testbed(testbed, "release")
                del self.unhealthy_testbeds[testbed]
                self.build_testbeds_list.remove(testbed)
        return


    def wait_pipelines_done(self, auth, sleep_time, build_timeout):
        # self.build_testbeds_list = list(self.unhealthy_testbeds.keys())
        logger.info("wait {} pipeline build {} ".format(len(self.build_testbeds_list), self.build_testbeds_list))

        if len(self.build_testbeds_list) == 0 :
            logger.info("current build_testbeds_list is empty, no need to wait sanity check ") 
            return

        if self.current_step == AUTO_RECOVERY_RC.REDEPLOY_UNHEALTHY_TESTBED:
            build_type = "redeploy"
        elif self.current_step == AUTO_RECOVERY_RC.SANITY_CHECK_UNHEALTHY_TESTBED:
            build_type = "sanity"
        else:
            raise RuntimeError('current step mismatch {}, should be in redeploy build {} or in sanity check {}'.format(self.current_step, AUTO_RECOVERY_RC.REDEPLOY_UNHEALTHY_TESTBED, AUTO_RECOVERY_RC.SANITY_CHECK_UNHEALTHY_TESTBED))

        remain_build_list = []
        start_time = time.time()

        if not self.debug_mode:
            time.sleep(sleep_time)

        while True:

            time_check = time.time()

            if (time_check - start_time) > build_timeout :
                logger.info("build timeout: start time {} current time {} remain testbeds {} ".format(start_time, time_check, self.build_testbeds_list))
                break

            if (len(self.build_testbeds_list) == 0) :
                logger.info("current build_testbeds_list is empty, break waiting pipeline ") 
                break

            for testbed in self.build_testbeds_list[:]:
                pipeline_url = "https://dev.azure.com/mssonic/internal/_apis/build/builds/" + str(self.unhealthy_testbeds[testbed]['buildID'][build_type]) + "/timeline?api-version=5.1"
                if self.verbose :
                    logger.info("get {} pipeline build status, url {} ".format(testbed, pipeline_url))

                get_build_records = requests.get(pipeline_url, auth=auth).json()

                build_complete = True

                for build_record in get_build_records["records"]:
                    if build_record['state'] == "completed" :
                        if build_record['result'] == "failed" :
                            logger.info("testbed {} build failed, state {}, result {}, build_complete {} ".format(testbed, build_record['state'], build_record['result'], build_complete))

                            if self.current_step == AUTO_RECOVERY_RC.REDEPLOY_UNHEALTHY_TESTBED:
                                self.update_testbeds_ToCusto(testbed, True, True, self.unhealthy_testbeds[testbed]['Powercycle'], 
                                                            "deploy failed#" + str(self.unhealthy_testbeds[testbed]['buildID']['redeploy']), None, "success", 0, "deploy build failed")
                            elif self.current_step == AUTO_RECOVERY_RC.SANITY_CHECK_UNHEALTHY_TESTBED:
                                self.update_testbeds_ToCusto(testbed, True, True, self.unhealthy_testbeds[testbed]['Powercycle'], 
                                                            "success#" + str(self.unhealthy_testbeds[testbed]['buildID']['redeploy']), 
                                                            "sanity failed#" + str(self.unhealthy_testbeds[testbed]['buildID']['sanity']), "success", 0, "sanity build failed")
                            else:
                                raise RuntimeError('current step mismatch {}, should be in redeploy build {} or in sanity check {}'.format(self.current_step, AUTO_RECOVERY_RC.REDEPLOY_UNHEALTHY_TESTBED, AUTO_RECOVERY_RC.SANITY_CHECK_UNHEALTHY_TESTBED))

                            self.lock_release_testbed(testbed, "release")
                            del self.unhealthy_testbeds[testbed]
                            self.build_testbeds_list.remove(testbed)
                            build_complete = False
                            break

                        elif build_record['result'] == "canceled":
                            logger.info("testbed {} build canceled, state {}, result {}, build_complete {} ".format(testbed, build_record['state'], build_record['result'], build_complete))

                            if self.current_step == AUTO_RECOVERY_RC.REDEPLOY_UNHEALTHY_TESTBED:
                                self.update_testbeds_ToCusto(testbed, True, True, self.unhealthy_testbeds[testbed]['Powercycle'], 
                                                            "deploy canceled#" + str(self.unhealthy_testbeds[testbed]['buildID']['redeploy']), None, "success", self.unhealthy_testbeds[testbed]['Priority'] + 1, "deploy build canceled")
                            elif self.current_step == AUTO_RECOVERY_RC.SANITY_CHECK_UNHEALTHY_TESTBED:
                                self.update_testbeds_ToCusto(testbed, True, True, self.unhealthy_testbeds[testbed]['Powercycle'], 
                                                            "success#" + str(self.unhealthy_testbeds[testbed]['buildID']['redeploy']), 
                                                            "sanity canceled#" + str(self.unhealthy_testbeds[testbed]['buildID']['sanity']), "success", self.unhealthy_testbeds[testbed]['Priority'] + 1, "sanity build canceled")
                            else:
                                raise RuntimeError('current step mismatch {}, should be in redeploy build {} or in sanity check {}'.format(self.current_step, AUTO_RECOVERY_RC.REDEPLOY_UNHEALTHY_TESTBED, AUTO_RECOVERY_RC.SANITY_CHECK_UNHEALTHY_TESTBED))

                            self.lock_release_testbed(testbed, "release")
                            del self.unhealthy_testbeds[testbed]
                            self.build_testbeds_list.remove(testbed)
                            build_complete = False
                            break

                    else :
                        # logger.info("not complete ")
                        build_complete = False
                        continue

                if build_complete == True :
                    logger.info("testbed {} build {} complete \n".format(testbed, self.unhealthy_testbeds[testbed]['buildID']))
                    self.build_testbeds_list.remove(testbed)
                    remain_build_list.append(testbed)

            if len(self.build_testbeds_list) > 0:
                time.sleep(sleep_time)
                    
        for testbed in self.build_testbeds_list[:]:
            logger.info("testbed {} build {} timeout, move to custo table ".format(testbed, self.unhealthy_testbeds[testbed]['buildID']))

            if self.current_step == AUTO_RECOVERY_RC.REDEPLOY_UNHEALTHY_TESTBED:
                self.update_testbeds_ToCusto(testbed, True, True, self.unhealthy_testbeds[testbed]['Powercycle'], 
                                            "deploy timeout#" + str(self.unhealthy_testbeds[testbed]['buildID']['redeploy']), None, "success", 0, "deploy build timeout")
            elif self.current_step == AUTO_RECOVERY_RC.SANITY_CHECK_UNHEALTHY_TESTBED:
                self.update_testbeds_ToCusto(testbed, True, True, self.unhealthy_testbeds[testbed]['Powercycle'], 
                                            "success#" + str(self.unhealthy_testbeds[testbed]['buildID']['redeploy']), 
                                            "sanity timeout#" + str(self.unhealthy_testbeds[testbed]['buildID']['sanity']), "success", 0, "sanity build timeout")
            else:
                raise RuntimeError('current step mismatch {}, should be in redeploy build {} or in sanity check {}'.format(self.current_step, AUTO_RECOVERY_RC.REDEPLOY_UNHEALTHY_TESTBED, AUTO_RECOVERY_RC.SANITY_CHECK_UNHEALTHY_TESTBED))


            self.lock_release_testbed(testbed, "release")

            del self.unhealthy_testbeds[testbed]
            self.build_testbeds_list.remove(testbed)

        if len(self.build_testbeds_list) != 0:
            logger.error("!!!! ERROR !!!!! build_testbeds_list should be emply; {} ".format(self.build_testbeds_list))

        self.build_testbeds_list = remain_build_list.copy()

        self.check_unhealthy_testbeds()
        return


    def update_testbeds_ToCusto(self, testbed, triggerIcM, isReachable, powerCycle, redeploy, sanityCheck, lockStatus, priority, summary):
        if self.verbose :
            logger.info("testbed: {}, triggerIcM: {}, Priority: {}, isReachable: {}, powerCycle: {}, redeploy: {}, sanityCheck: {}, lockStatus: {}, summary: {} ".format(testbed, triggerIcM, priority, isReachable, powerCycle, redeploy, sanityCheck, lockStatus, summary))
        self.unhealthy_testbeds_ToCusto[testbed] = {'UTCTimestamp' : str(datetime.datetime.utcnow()), 
                                                    'TestbedName'  : self.unhealthy_testbeds[testbed]['TestbedName'], 
                                                    'DutName'      : self.unhealthy_testbeds[testbed]['DutName'],
                                                    'DutIP'        : self.unhealthy_testbeds[testbed]['DutIP'],
                                                    'Console'      : self.unhealthy_testbeds[testbed]['Console'],
                                                    'TriggerIcM'   : triggerIcM, 
                                                    'IsReachable'  : isReachable, 
                                                    'PowerCycle'   : powerCycle, 
                                                    'Redeploy'     : redeploy, 
                                                    'SanityCheck'  : sanityCheck, 
                                                    'LockStatus'   : lockStatus,
                                                    'Priority'     : priority,
                                                    'Summary'      : summary}
        return


    def check_unhealthy_testbeds(self):
        # if self.verbose or self.debug_mode :
        unhealthy_count = len(self.unhealthy_testbeds.keys())
        toCusto_count = len(self.unhealthy_testbeds_ToCusto.keys())
        logger.info("##### current loop: {}, {} in curr build list {}".format(self.current_loop, len(self.build_testbeds_list), self.build_testbeds_list))
        logger.info("##### current step: {}, {} in unhealthy table ".format(AUTO_RECOVERY_RC.meaning(self.current_step), unhealthy_count))
        for testbed in self.unhealthy_testbeds.keys() :
            logger.info("##### {} ".format(self.unhealthy_testbeds[testbed]))
        logger.info("##### current step: {}, {} in to custo table ".format(AUTO_RECOVERY_RC.meaning(self.current_step), toCusto_count))
        for testbed in self.unhealthy_testbeds_ToCusto.keys() :
            logger.info("##### {} ".format(self.unhealthy_testbeds_ToCusto[testbed]))

        if ((unhealthy_count + toCusto_count) != self.unhealthy_testbeds_count) :
            logger.info("##### current step: {} unhealthy count {} toCusto_count {} collect count {} ".format(AUTO_RECOVERY_RC.meaning(self.current_step), unhealthy_count, toCusto_count, self.unhealthy_testbeds_count))
            logger.info("##### unhealthy table {}".format(self.unhealthy_testbeds))
            logger.info("##### to custo table  {}".format(self.unhealthy_testbeds_ToCusto))
            raise RuntimeError('unhealthy testbeds count mismatch')
        return 


    def test_lock(self):
        for testbed in self.unhealthy_testbeds.copy() :
            if self.verbose :
                logger.info("lock testbed {} ".format(testbed))

            rst, lock_statue = self.lock_release_testbed(testbed, "lock")
            logger.info("{} testbed {} status {} ".format("lock", testbed, lock_statue))

        for testbed in self.unhealthy_testbeds.copy() :
            if self.verbose :
                logger.info("release testbed {} ".format(testbed))

            rst, lock_statue = self.lock_release_testbed(testbed, "release")
            logger.info("{} testbed {} status {} ".format("release", testbed, lock_statue))

        return


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Completeness level')

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="test auto recovery")

    parser.add_argument(
        '-v', '--verbose', help='Set verbose output', action='store_true',
        required=False, default=False
    )

    parser.add_argument(
        '-d', '--debug', help='Set debug mode; no power cycle/redeploy in debug mode', action='store_true',
        required=False, default=False
    )

    parser.add_argument(
        '-s', '--sanity_check', help='with Sanity check', action='store_true',
        required=False, default=False
    )

    parser.add_argument(
        '-g', '--golden_image', help='upgrade with golden image', action='store_true',
        required=False, default=False
    )

    parser.add_argument(
        '-n', '--testbedName', help='input testbed name', type=str,
        required=False
    )

    parser.add_argument(
        '-p', '--agent_pool', help='input agent pool; nightly,nightly-svc,nightly-bjw', type=str,
        choices = ['nightly', 'nightly-svc', 'nightly-bjw'],
        required=True, default='nightly'
    )

    args = parser.parse_args()
    logger.info("verbose {} debug mode {} sanity check {} testbedName {} golden_image {} agent_pool {}".format(args.verbose, args.debug, args.sanity_check, args.testbedName, args.golden_image, args.agent_pool))

    autoRecovery = Testbeds_auto_recovery(verbose = args.verbose, debug_mode = args.debug, sanity_check = args.sanity_check, golden_image = args.golden_image, agent_pool = args.agent_pool)
    autoRecovery.start_time = time.time()

    # collect unhealthy testbeds
    rst = AUTO_RECOVERY_RC.COLLECT_UNHEALTHY_TESTBED
    if args.testbedName == None:
        autoRecovery.collect_unhealthy_testbeds()
    else:
        autoRecovery.testbedName = args.testbedName
        autoRecovery.parser_unhealthy_testbeds()

    if autoRecovery.verbose :
        logger.info("collect {} unhealthy testbeds ".format(autoRecovery.unhealthy_testbeds_count))
        for testbed in autoRecovery.unhealthy_testbeds.keys() :
            logger.info("unhealthy testbeds {} ".format(autoRecovery.unhealthy_testbeds[testbed]))

    while len(autoRecovery.unhealthy_testbeds.keys()) > 0 :
        # lock unhealthy testbeds before auto recovery
        autoRecovery.lock_unhealthy_testbeds()

        # ping before power cycle
        autoRecovery.ping_unhealthy_testbeds()

        # power cycle
        autoRecovery.powercycle_unhealthy_testbeds()

        # ping after power cycle
        autoRecovery.ping_unhealthy_testbeds_after_powercycle()

        # redeploy
        autoRecovery.redeploy_unhealthy_testbeds()

        # sanity check
        autoRecovery.sanity_unhealthy_testbeds()

        # unlock unhealthy testbeds
        autoRecovery.unlock_unhealthy_testbeds()

        autoRecovery.current_loop = autoRecovery.current_loop + 1

    # upload unhealthy testbeds table to custo
    if not autoRecovery.debug_mode and args.testbedName == None :
        autoRecovery.upload_unhealthy_testbeds_to_custo()

    logger.info("testbeds auto recovery complete ")




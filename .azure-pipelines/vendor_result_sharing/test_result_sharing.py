#!/bin/env python3

import os
import sys
import logging
import shutil
import argparse
from azure.kusto.data import KustoConnectionStringBuilder, KustoClient
from azure.storage.blob import BlobServiceClient, BlobClient
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
try:
    from azure.kusto.ingest import KustoIngestClient
except ImportError:
    from azure.kusto.ingest import QueuedIngestClient as KustoIngestClient
from azure.kusto.ingest import IngestionProperties
# Resolve azure.kusto.ingest compatibility issue
try:
    from azure.kusto.ingest import DataFormat
except ImportError:
    from azure.kusto.data.data_format import DataFormat
import tempfile
import json
from datetime import datetime
# Install the following package before running this program
# pip install azure-storage-blob azure-identity


logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s :%(name)s:%(lineno)d %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


DATABASE = 'SonicTestData'
VENDOR_ACCOUNT_URL = 'https://sonicvendorresult.blob.core.windows.net'
NIGHTLY_TEST_ACCOUNT_URL = 'https://sonicelastictestprodsa.blob.core.windows.net'
NIGHTLY_TEST_CONTAINER_NAME = 'nightlytest'
VENDOR_CONTAINER = {'arista', 'brcm', 'cisco', 'mellanox'}
CASE_SHRESHOLD = int(800)
PASSRATE_SHRESHOLD = float(90.0)
TEST_RESULT_SHARE_LOG_TABLE = "TestResultSharingLogData"
TABLE_FORMAT_LOOKUP = {
    TEST_RESULT_SHARE_LOG_TABLE: DataFormat.JSON
}
TABLE_MAPPING_LOOKUP = {
    TEST_RESULT_SHARE_LOG_TABLE: "TestResultSharingLogDataMappingV1"
}


class KustoChecker(object):

    def __init__(self, cluster, tenant_id, client_id, client_key, database):
        self.ingest_cluster = cluster
        self.cluster = cluster.replace('ingest-', '')
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_key = client_key
        self.database = database

        self.logger = logging.getLogger('KustoChecker')

        kcsb = KustoConnectionStringBuilder.with_aad_application_key_authentication(self.cluster,
                                                                                    self.client_id,
                                                                                    self.client_key,
                                                                                    self.tenant_id
                                                                                    )
        kcsb_ingest = KustoConnectionStringBuilder.with_aad_application_key_authentication(self.ingest_cluster,
                                                                                           self.client_id,
                                                                                           self.client_key,
                                                                                           self.tenant_id
                                                                                           )

        self.client = KustoClient(kcsb)
        self.ingest_client = KustoIngestClient(kcsb_ingest)

    def query(self, query):
        self.logger.debug('Query String: {}'.format(query))
        return self.client.execute(self.database, query)

    def query_highest_pass_rate(self, HardwareSku=None, TopologyType=None, BranchName=None, BuildId=None, Vendor=None):
        """
        Query the highest pass rate for each HardwareSku, Topology, Branch for past 7 days
        return: list[{Vendor,BuildId,HardwareSku,TopologyType,BranchName,RunDate,RunWeek,OSVersion,SuccessRate,CasesRun}]
        """
        hardwaresku_q = '| where HardwareSku contains "{}"'.format(HardwareSku) if HardwareSku else ''
        TopologyType_q = '| where TopologyType contains "{}"'.format(TopologyType) if TopologyType else ''
        BranchName_q = '| where BranchName contains "{}"'.format(BranchName) if BranchName else ''
        BuildId_q = '| where BuildId contains "{}"'.format(BuildId) if BuildId else ''
        Vendor_q = '| where Vendor contains "{}"'.format(Vendor) if Vendor else ''
        query_str = '''
            let IncludeBranchList = dynamic(['20230531', '20231105', '20231131']);
            let BroadcomList = dynamic(['s6100','dx010','s6000','e1031','3164']);
            let CiscoList = dynamic(["8102","8101","8111"]);
            let MellanoxList = dynamic(["3800", "2700", "4700","4600c"]);
            let AristaList = dynamic([]);
            let MarvellList = dynamic(["7215"]);
            let TopologyList = dynamic(['t0', 't1', 'm0', 'mx', 'dualtor']);
            let VendorList = dynamic(['arista', 'brcm', 'cisco', 'mellanox']);
            TestReportUnionData
            | where UploadTimestamp > ago(7d)
            | where TestbedName != ''
            | where Result != "skipped"
            | where TestType == "ElasticTest"
            | where PipeStatus == "FINISHED"
            | where BranchName in (IncludeBranchList)
            | where TopologyType in (TopologyList)
            | extend ResultExpectation = case(Result in ("success", "xfail_expected", "xfail_forgive","xfail_skipped"), "expected", Result in ("xfail_unexpected"), "unexpected", Result)
            | summarize CasesRun = count(), Successes = countif(ResultExpectation == "expected") by BuildId,OSVersion,RunDate,BranchName,HardwareSku,TopologyType,AsicType
            | extend SuccessRate = case(Successes == 0 or CasesRun == 0,round(0),round(todouble((Successes)* 100) /todouble(CasesRun),2))
            {} {} {} {}
            | summarize arg_max(SuccessRate, *) by BuildId
            | extend RunWeek = week_of_year(RunDate)
            | summarize arg_max(SuccessRate, *) by HardwareSku,TopologyType,RunWeek,BranchName
            | extend Vendor = case(HardwareSku startswith "Arista", "arista",
                                HardwareSku startswith "Cisco", "cisco",
                                HardwareSku startswith "Mellanox", "mellanox",
                                HardwareSku has_any (MellanoxList), "mellanox",
                                HardwareSku has_any (BroadcomList), "brcm", "unknow" )
            | where Vendor in (VendorList)
            | project Vendor,BuildId,HardwareSku,TopologyType,BranchName,RunDate,RunWeek,OSVersion,SuccessRate,CasesRun
            {}
        '''.format(hardwaresku_q, TopologyType_q, BranchName_q, BuildId_q, Vendor_q)
        logger.info('Query highest pass rate for each HardwareSku, Topology and Branch for past 7 days:{}'.format(query_str))

        result = self.query(query_str)
        highest_pass_rate = result.primary_results[0].to_dict()['data']
        print(highest_pass_rate)
        return highest_pass_rate

    def upload_data(self, report_data):
        self._ingest_data(TEST_RESULT_SHARE_LOG_TABLE, report_data)
        return

    def _ingest_data(self, table, data):
        props = IngestionProperties(
            database=self.database,
            table=table,
            data_format=TABLE_FORMAT_LOOKUP[table],
            ingestion_mapping_reference=TABLE_MAPPING_LOOKUP[table]
        )

        with tempfile.NamedTemporaryFile(mode="w+") as temp:
            if isinstance(data, list):
                temp.writelines(
                    '\n'.join([json.dumps(entry) for entry in data]))
            else:
                temp.write(json.dumps(data))
            temp.seek(0)

            if self.ingest_client:
                logger.info("Ingest to backup cluster...")
                self.ingest_client.ingest_from_file(temp.name, ingestion_properties=props)
        return


class AzureBlobConnecter(object):

    def __init__(self, account_url, token=None):
        self.account_url = account_url

        if token:
            self.token = token
        else:
            raise RuntimeError('Could not load Storage credentials from environment')

        self.http_logger = logging.getLogger('azure.core.pipeline.policies.http_logging_policy')
        self.http_logger.setLevel(logging.WARNING)

        self.blob_service_client = BlobServiceClient(account_url=self.account_url, credential=self.token)

        logger.info("Connected to Azure Blob Storage {} successfully".format(self.account_url))

    def connect_to_container(self, container_name):
        container = self.blob_service_client.get_container_client(container=container_name)
        container_list = container.list_blobs()
        for blob in container_list:
            logger.info(blob.name + '\n')

        return container

    def get_buildid_from_container(self, container_name):
        container = self.blob_service_client.get_container_client(container=container_name)
        buildid = []
        container_list = container.list_blobs(name_starts_with="2024")
        for blob in container_list:
            buildid.append(blob.name.split('/')[1].split('_')[0])
        logger.info("Buildid list: {} in container {}".format(buildid, container_name))

        return buildid

    def upload_artifacts_to_container_with_tag(self, container_name, artifact, tag):
        try:
            # Create a ContainerClient
            container_client = self.blob_service_client.get_container_client(container_name)

            # upload artifact
            with open(file=artifact, mode="rb") as data:
                blob_client = container_client.upload_blob(name=artifact, data=data, tags=tag)

            logger.info("upload artifact {} to {} with tag:{}".format(artifact, container_name, tag))

        except ResourceExistsError as ex:
            logger.error("The artifact {} already exists. Error: {}".format(artifact, ex))

        except Exception as ex:
            logger.error("Error {} occurred when uploading {} to container {}".format(ex, artifact, container_name))

    def upload_artifacts_to_container(self, container_name, artifact, blob_name):
        logger.debug("Tyr to upload artifacts to container {} with blob name {} from local file {}".format(container_name, blob_name, artifact))
        try:
            # Create a BlobClient for the artifact
            blob_client = self.blob_service_client.get_blob_client(container=container_name, blob=blob_name)

            # upload artifact
            with open(artifact, "rb") as data:
                blob_client.upload_blob(data=data, overwrite=True)

            logger.info("uploaded artifact {} to {}".format(artifact, blob_name))

        except ResourceExistsError as ex:
            logger.error("The artifact {} already exists. Error: {}".format(artifact, ex))

        except Exception as ex:
            logger.error("Error {} occurred when uploading {} to container {}".format(ex, artifact, container_name))

        logger.debug("Upload artifacts to container {} with blob name {} from local file {} DONE".format(container_name, blob_name, artifact))

    def download_artifacts_from_container(self, container_name, blob_name, local_file_path):
        try:
            # Create a BlobClient for the artifact
            blob_client = BlobClient(account_url=self.account_url,
                                     container_name=container_name,
                                     credential=self.token,
                                     blob_name=blob_name,
                                     max_single_get_size=1024 * 1024 * 32,  # 32 MiB
                                     max_chunk_get_size=1024 * 1024 * 4  # 4 MiB
                                    )

            # download artifact to the local file
            with open(local_file_path, "wb") as download_file:
                download_file.write(blob_client.download_blob().readall())

            logger.info("download artifact {} to {}".format(blob_name, local_file_path))

        except ResourceNotFoundError as ex:
            logger.error("The artifact {} or container {} does not exist. Error: {}".format(blob_name, container_name, ex))

        except Exception as ex:
            logger.error("Error {} occurred when downloading {} from container {}".format(ex, blob_name, container_name))

    def download_artifacts_from_container_recursively(self, container_name, folder_name, local_path):
        logger.debug("Download artifacts from container {} with folder {} to local path {}".format(container_name, folder_name, local_path))
        os.makedirs(local_path, exist_ok=True)

        container_client = self.blob_service_client.get_container_client(container=container_name)
        for blob in container_client.list_blobs(name_starts_with=folder_name):
            blob_name = blob.name
            if "/" in blob_name:
                head, tail = os.path.split(blob_name)
                logger.info("head: {}, tail: {}".format(head, tail))
                if (os.path.isdir(local_path + "/" + head)):
                    logger.info("Directory {} exists, skip creating".format(local_path + "/" + head))
                    self.download_artifacts_from_container(container_name, blob_name, local_path + "/" + head + "/" + tail)
                else:
                    logger.info("Creating directory {}".format(local_path + "/" + head))
                    os.makedirs(local_path + "/" + head, exist_ok=True)
                    self.download_artifacts_from_container(container_name, blob_name, local_path + "/" + head + "/" + tail)
            else:
                self.download_artifacts_from_container(container_name, blob_name, local_path + "/" + blob_name)

        logger.debug("Download artifacts from container {} with folder {} to local path {} DONE".format(container_name, folder_name, local_path))


def create_kusto_checker():

    ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP")
    tenant_id = os.getenv("TEST_REPORT_AAD_TENANT_ID_BACKUP")
    client_id = os.getenv("TEST_REPORT_AAD_CLIENT_ID_BACKUP")
    client_key = os.getenv("TEST_REPORT_AAD_CLIENT_KEY_BACKUP")

    if not all([ingest_cluster, tenant_id, client_id, client_key]):
        raise RuntimeError('Could not load Kusto credentials from environment')

    return KustoChecker(ingest_cluster, tenant_id, client_id, client_key, DATABASE)


def main(args):

    topology = args.topology if args.topology != "All" else None
    branch = args.branch if args.branch != "All" else None
    hardwaresku = args.hardwaresku if args.hardwaresku != "All" else None
    buildid = args.buildid if args.buildid != "All" else None
    vendor = args.vendor if args.vendor != "All" else None

    kustochecker = create_kusto_checker()
    vendor_sharing_storage_token = os.getenv("VENDOR_SHARING_SAS_TOKEN")
    nightly_test_storage_token = os.getenv("NIGHTLY_TEST_SAS_TOKEN")
    nightly_test_storage_connecter = AzureBlobConnecter(NIGHTLY_TEST_ACCOUNT_URL, nightly_test_storage_token)
    vendor_sharing_storage_connecter = AzureBlobConnecter(VENDOR_ACCOUNT_URL, vendor_sharing_storage_token)

    result = kustochecker.query_highest_pass_rate(HardwareSku=hardwaresku, TopologyType=topology, BranchName=branch, BuildId=buildid, Vendor=vendor)
    total_count = len(result)
    logger.info('Total count of test result: {}'.format(total_count))

    upload_date = datetime.now().strftime("%Y%m%d")
    ingested_time = str(datetime.now())

    base_path = os.getcwd()
    logger.info('Current working directory: {}, current date:{}'.format(base_path, upload_date))

    counter_map = dict()
    if vendor:
        counter_map[vendor] = 0
    else:
        counter_map['arista'] = 0
        counter_map['brcm'] = 0
        counter_map['cisco'] = 0
        counter_map['mellanox'] = 0

    report_json = []

    buildid_list = dict()
    if vendor:
        buildid_list[vendor] = vendor_sharing_storage_connecter.get_buildid_from_container(vendor + 'testresult')
    else:
        for vendor in VENDOR_CONTAINER:
            buildid_list[vendor] = vendor_sharing_storage_connecter.get_buildid_from_container(vendor + 'testresult')

    for res in result:
        temp_json = dict()
        temp_json.update({'upload_date': ingested_time, 'upload_status': 'False'})

        buildid = res['BuildId']
        hardwaresku = res['HardwareSku']
        topology = res['TopologyType']
        branch = res['BranchName']
        vendor = res['Vendor']
        run_date = res['RunDate']
        os_version = res['OSVersion']
        cases_run = int(res['CasesRun'])
        success_rate = res['SuccessRate']
        logger.info('BuildId: {}, HardwareSku: {}, TopologyType: {}, BranchName: {}, Vendor: {}, RunDate: {}, OSVersion: {}, CasesRun: {}, SuccessRate: {}'.format(buildid, hardwaresku, topology, branch, vendor, run_date, os_version, cases_run, success_rate))

        temp_json.update({'buildid': buildid, 'hardwaresku': hardwaresku, 'topology': topology, 'branch': branch, 'vendor': vendor, 'run_date': str(run_date), 'os_version': os_version, 'cases_run': cases_run, 'success_rate': success_rate})
        logger.info("current temp_json: {}".format(temp_json))

        if vendor != "cisco" and topology == "dualtor":
            # Dualtor test result should from azure pipeline besides cisco
            logger.info('Topology {} is not supported for vendor {}, ignore'.format(topology, vendor))
            report_json.append(temp_json)
            continue

        if vendor not in VENDOR_CONTAINER:
            logger.info('Vendor {} is not in the vendor list, ignore'.format(vendor))
            report_json.append(temp_json)
            continue

        if buildid in buildid_list[vendor]:
            logger.info('BuildId: {} already exists in container {}, ignore'.format(buildid, vendor + 'testresult'))
            report_json.append(temp_json)
            continue

        if cases_run < CASE_SHRESHOLD and vendor != 'cisco':
            logger.info('Total CassesRun: {} is less than 800, may be not a full run, ingore'.format(str(cases_run)))
            report_json.append(temp_json)
            continue

        if float(success_rate) < PASSRATE_SHRESHOLD:
            logger.info('SuccessRate: {} is less than 90%, do not upload this, ingore'.format(str(success_rate)))
            report_json.append(temp_json)
            continue

        nightly_test_storage_connecter.download_artifacts_from_container_recursively(NIGHTLY_TEST_CONTAINER_NAME, buildid, base_path)
        shutil.make_archive(buildid, 'zip', base_path)
        # artifact name is buildid.zip
        local_artifact_path = buildid + '.zip'

        vendor_container_name = vendor + 'testresult'

        remote_file_path = upload_date + '/' + buildid + '_' + hardwaresku + '_' + topology + '_' + str(os_version) + '_' + str(success_rate) + '.zip'

        logger.debug('Staring upload artifact {} to container {} with blob name:{}'.format(local_artifact_path, vendor_container_name, remote_file_path))
        vendor_sharing_storage_connecter.upload_artifacts_to_container(container_name=vendor_container_name, artifact=local_artifact_path, blob_name=remote_file_path)

        # update counter and log data
        counter_map[vendor] += 1
        temp_json.update({'upload_status': 'True'})
        report_json.append(temp_json)
        shutil.rmtree(base_path + '/' + buildid)
        os.remove(local_artifact_path)

    logger.info('Actual upload to azure storage counter summary: {}'.format(counter_map))
    logger.info('Will ingest {} records to kusto'.format(len(report_json)))
    logger.info('Upload detail summary to kusto: {}'.format(report_json))
    kustochecker.upload_data(report_json)

    return


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Sharing nightly test results with vendors")

    parser.add_argument('-t', '--topology',
                        type=str,
                        dest='topology',
                        default="All",
                        choices=['t0', 't1', 'm0', 'mx', 'All'],
                        help='Topology type, t0, t1, m0 or mx, default is all'
                        )

    parser.add_argument('-b', '--branch',
                        type=str,
                        dest='branch',
                        default="All",
                        choices=['20230531', '20231105', 'All'],
                        help='Branch name, 20230531 or 20231105'
                        )

    parser.add_argument('-s', '--sku',
                        type=str,
                        dest='hardwaresku',
                        default="All",
                        help='Hardware sku'
                        )

    parser.add_argument('-i', '--buildid',
                        type=str,
                        dest='buildid',
                        default="All",
                        help='Build id'
                        )

    parser.add_argument('-v', '--vendor',
                        type=str,
                        dest='vendor',
                        default="All",
                        help='Vendor name'
                        )

    args = parser.parse_args()

    main(args)

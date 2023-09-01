'''
This script is used to collect all the nightly pipelines and category them into different files which are used for skywatch https://aka.ms/skywatch.
The output files are located in output folder.
Step 1: Create output folder
Step 2: python collect_powerbi_category.py
Step 3: Output files will be generaged in output folder
Step 4: Upload these files to https://microsoft.sharepoint.com/teams/Aznet/Engineering%20Q%20%20Z/Forms/AllItems.aspx?id=%2Fteams%2FAznet%2FEngineering%20Q%20%20Z%2FSONIC%2FTest%2Fnightly%5Fguard%2FPowerBI%2Foutput&viewid=7fb2dd98%2Da86b%2D47de%2D89ca%2D933d8e419fd6
Step 5: Run Program.cs with dotnet run, follow the instruction in Program.cs
Step 6: Refresh the PowerBI dataset and publish it to SONiC workspace

output files:
-rwxrwxrwx 1 zhaohuisun zhaohuisun  3303 Aug 31 18:11 202012Nightly.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun 10789 Aug 31 18:11 202012NightlyMeasure.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun  2877 Aug 31 18:11 202012NightlySuccessRate.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun  3927 Aug 31 18:11 202012NightlySuccessRate.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun  6691 Aug 31 18:11 202205Nightly.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun 21542 Aug 31 18:11 202205NightlyMeasure.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun  5697 Aug 31 18:11 202205NightlySuccessRate.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun  7804 Aug 31 18:11 202205NightlySuccessRate.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun  1337 Aug 31 18:11 202305Nightly.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun  4301 Aug 31 18:11 202305NightlyMeasure.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun  1587 Aug 31 18:11 202305NightlySuccessRate.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun  2163 Aug 31 18:11 202305NightlySuccessRate.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun  6756 Aug 31 18:11 AristaNightly.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun 21755 Aug 31 18:11 AristaNightlyMeasure.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun  1140 Aug 31 18:11 CelesticaNightly.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun  3746 Aug 31 18:11 CelesticaNightlyMeasure.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun   768 Aug 31 18:11 CiscoNightly.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun  2522 Aug 31 18:11 CiscoNightlyMeasure.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun  1230 Aug 31 18:11 DellNightly.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun  3924 Aug 31 18:11 DellNightlyMeasure.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun  1973 Aug 31 18:11 InternalNightly.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun  6390 Aug 31 18:11 InternalNightlyMeasure.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun  2249 Aug 31 18:11 InternalNightlySuccessRate.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun  3048 Aug 31 18:11 InternalNightlySuccessRate.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun   525 Aug 31 18:11 MasterNightly.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun  1696 Aug 31 18:11 MasterNightlyMeasure.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun   643 Aug 31 18:11 MasterNightlySuccessRate.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun   862 Aug 31 18:11 MasterNightlySuccessRate.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun  3239 Aug 31 18:11 MellanoxNightly.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun 10273 Aug 31 18:11 MellanoxNightlyMeasure.txt
-rwxrwxrwx 1 zhaohuisun zhaohuisun   542 Aug 31 18:11 NokiaNightly.csv
-rwxrwxrwx 1 zhaohuisun zhaohuisun  1744 Aug 31 18:11 NokiaNightlyMeasure.txt
'''
from __future__ import print_function

import json
import os
import yaml
import requests

from datetime import datetime
from datetime import timedelta

from crontab import CronTab
import pandas as pd
import csv

BASE_URL = 'https://dev.azure.com/mssonic/internal/_apis'
TOKEN = os.environ.get('AZURE_DEVOPS_MSSONIC_TOKEN')
if not TOKEN:
    raise Exception('Must export environment variable AZURE_DEVOPS_MSSONIC_TOKEN')
AUTH = ('', TOKEN)

FOLDER = "output/"
urls = {
    'build_definitions': BASE_URL + '/build/definitions',
    'git_item': BASE_URL + '/git/repositories/{}/items'
}


def get_nightly_build_definitions():
    """Get list of enabled build definitions under folder '\\Nightly'

    Returns:
        list: List of build definitions. Each item is a dict.
    """
    build_definitions = requests.get(urls['build_definitions'], auth=AUTH).json()['value']
    nightly_pipeline_list = []
    
    for build in build_definitions:
        nightly_pipeline = {}
        enabled = False
        nightly = False

        if 'queueStatus' in build and build['queueStatus'] == 'enabled':
            enabled = True
        if 'path' in build and build['path'].startswith('\\Nightly') or build['path'].startswith('\\Elastictest') and not build['path'].startswith('\\Nightly-Hawk') and not '\\Disabled' in build['path']:
            nightly = True
        if not enabled or not nightly:
            continue
        if '-t2-' in build['name'].lower():
            print("====Skip T2 pipeline so far. {}".format(build['name']))
            continue
        if '\\rdma' in build['path'].lower() or '\\wan' in build['path'].lower() or '\\intel' in build['path'].lower():
            print("====Skip RDMA/WAN/Intel pipeline so far. {}".format(build['name']))
            continue
            
        nightly_pipeline['pipeline_name'] = build['name']
        nightly_pipeline['pipeline_url'] = build['_links']['web']['href']
        nightly_pipeline['pipeline_id'] = build['id']
        nightly_pipeline['test_type'] = 'Elastictest' if build['path'].startswith('\\Elastictest') else 'Nightly'
        vendor = build['path'].split('\\')[-1]
        nightly_pipeline['vendor'] = vendor
        build_detail = requests.get(build['url'], auth=AUTH).json()
        branch = build_detail['repository']['defaultBranch'].lstrip('refs/heads/')
        nightly_pipeline['branch'] = branch

        repo_id = build_detail['repository']['id']
        yamlFileName = build_detail['process']['yamlFilename']
        print("yamlFileName: {}".format(yamlFileName))
        pipeline_yaml = yaml.safe_load(get_git_item(repo_id, branch, yamlFileName))
        yaml_result = extract_pipeline_info(pipeline_yaml)

        nightly_pipeline['testbed'] = yaml_result['testbed']
        nightly_pipeline['branch'] = yaml_result['branch'] if yaml_result['branch'] else branch
        if yaml_result['branch'] != branch:
            print("!!!!!!!!!branch not match {} : {} != {}".format(build['name'], yaml_result['branch'], branch))
        if not yaml_result['testbed']:
            print("!!!!!!!!!testbed not found {}".format(build['name']))
            continue
        name = nightly_pipeline['pipeline_name']
        if 'azd' in name or '3164' in name or 'e1031' in name or 'pikez' in name:
            print("====Skip azd/3164/e1031/pikez pipelines {}".format(nightly_pipeline['pipeline_name']))
            continue
        if nightly_pipeline['branch'] not in ['master', 'internal', 'internal-202012', 'internal-202205', 'internal-202305']:
            print("=====Skip private branch {} for pipeline {}".format(nightly_pipeline['branch'], nightly_pipeline['pipeline_name']))
            continue
        print("{}\t{}\t{}\t{}\t{}".format(build['name'], build['id'], nightly_pipeline['branch'], vendor, nightly_pipeline['testbed']))

        nightly_pipeline_list.append(nightly_pipeline)

    return nightly_pipeline_list


def get_git_item(repo, branch, path):
    url = urls['git_item'].format(repo)
    params = {
        'path': path,
        'versionDescriptor.versionType': 'branch',
        'versionDescriptor.version': branch
    }
    return requests.get(url, params=params, auth=AUTH).text


def extract_pipeline_info(pipeline):
    """Extract schedule information from dict loaded from pipeline yaml file.

    Args:
        pipeline (dict): Dict loaded from pipeline yaml file.

    Returns:
        dict: Dict contains testbed information and its schedules information.
    """
    res = {
        'testbed': '',
        'branch': '',
        'crons': []
    }
    if 'parameters' in pipeline:
        for parameter in pipeline['parameters']:
            if 'name' in parameter and parameter['name'] == 'TESTBED_NAME':
                res['testbed'] = parameter.get('default', '')
                break
    if 'schedules' in pipeline:
        for schedule in pipeline['schedules']:
            branches = schedule.get('branches', [])
            if branches and 'include' in branches:
                branch = branches['include']
                res['branch'] = branch[0]
            if schedule['always']:
                res['crons'].append(schedule['cron'])
    return res


def get_yesterday_time_range():
    """Get start and end time of calendar day of yesterday.

    Returns:
        tuple: A tuple of two items. The first item is start datetime, the second item is end datetime.
    """
    utcnow = datetime.utcnow()
    end = datetime(utcnow.year, utcnow.month, utcnow.day)
    start = end - timedelta(days=1)
    return start, end


def get_yesterday_schedules(cron, start, end):
    """Get hits in yesterday based on crontab style string.

    Args:
        cron (str): Crontab style string.
        start (datetime): Start datetime of yesterday.
        end (datetime): End datetime of yesterday.

    Returns:
        [type]: [description]
    """
    tab = CronTab(cron)

    timestamps = []
    while True:
        previous = datetime.fromtimestamp(tab.previous(now=end, delta=False, default_utc=True))
        if previous >= start:
            timestamps.insert(0, previous)
            end = previous
        else:
            break
    return timestamps


def parse_testbeds_crons(build_definitions):
    """Find out all the nightly test pipelines that have scheduled runs.

    Args:
        build_definitions (list of dict): List of all pipeline definitions retrived from AzDevOps API.

    Returns:
        dict: Dict of parsed nightly test runs for all testbeds.
    """
    testbeds_crons = {}
    for build in build_definitions:
        build_detail = requests.get(build['url'], auth=AUTH).json()
        repo_id = build_detail['repository']['id']
        branch = build_detail['repository']['defaultBranch'].lstrip('refs/heads/')
        yamlFileName = build_detail['process']['yamlFilename']
        pipeline_yaml = yaml.safe_load(get_git_item(repo_id, branch, yamlFileName))
        tb_cron = extract_pipeline_info(pipeline_yaml)
        if tb_cron['testbed']:
            testbed = tb_cron['testbed']
            crons = tb_cron['crons']
            if testbed in testbeds_crons:
                testbeds_crons[testbed]['crons'].extend(crons)
            else:
                testbeds_crons[testbed] = {
                    'crons': crons
                }
    return testbeds_crons


def generate_pipeline_status_measure(pipeline_info, extend_name):
    """Generate measure name for each pipeline.

    Args:
        pipeline_info (dict): Dict of parsed nightly test runs for all testbeds.
        vendor (str): vendor name.

    Returns:
        list: List of pipeline info with measure name.
    """
    pipeline_dict = {}
    pipeline_dict = pipeline_info.copy()

    measure_name = str(pipeline_dict['index']) + " " + pipeline_dict["pipeline_name"] + "_" + extend_name
    pipeline_dict["table"] = "PipelineRuns"
    pipeline_dict["measure_name"] = measure_name
    pipeline_dict["measure_content"] = '''
CALCULATE(
  IF(
      ISBLANK(SUM(PipelineRuns[SucceededCount])),
      3,
      IF(
          SUM(PipelineRuns[SucceededCount]) = 1,
          5,
          IF(
              SUM(PipelineRuns[CanceledCount]) = 1,
              4,
              1
          )
      )
  ),
  PipelineRuns[PipelineName] = "{}",
  PipelineRuns[BranchName] = "{}"
)'''.format(pipeline_dict["pipeline_name"], pipeline_info['branch'])

    return pipeline_dict

def generate_successrate_measure(index, pipeline_info, branch, testbed):
    """Generate measure name for each pipeline.

    Args:
        pipeline_info (dict): Dict of parsed nightly test runs for all testbeds.
        vendor (str): vendor name.

    Returns:
        list: List of pipeline info with measure name.
    """
    pipeline_dict = {}
    pipeline_dict = pipeline_info.copy()
    pipeline_dict['index'] = index
    if not testbed:
        testbed = pipeline_dict["testbed"]
    pipeline_dict["category"] = testbed + "_" + branch
    measure_name = str(index) + " " + testbed + "_" + branch
    pipeline_dict["table"] = "SONiCKusto"
    pipeline_dict["measure_name"] = measure_name
    if branch == 'master':
        branch_name = "master"
    elif branch == 'internal':
        branch_name = 'internal'
    elif branch == '202012':
        branch_name = '20201231'
    elif branch == '202205':
        branch_name = '20220531'
    elif branch == '202305':
        branch_name = '20230531'
    pipeline_dict["measure_content"] = '''
CALCULATE(
    MAX(SONiCKusto[SuccessRate]),
    SONiCKusto[TestbedName] = "{}",
    SONiCKusto[BranchName] = "{}"
)'''.format(testbed, branch_name)

    return pipeline_dict


def save_to_files(pipeline_list, vendor_or_branch, success_rate_pipeline_list=None, is_successrate=False):
    keys_to_save = ['index','pipeline_name','pipeline_url']
    # df = pd.DataFrame([{k: d[k] for k in keys_to_save} for d in pipeline_list])
    csv_list = [{k: d[k] for k in keys_to_save} for d in pipeline_list]

    excel_file_path = FOLDER + vendor_or_branch.capitalize() + "Nightly" + ".csv"
    
    measure_file_path = FOLDER + vendor_or_branch.capitalize() + "NightlyMeasure" + ".txt"
    successrate_file_path = None

    with open(excel_file_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=keys_to_save)
        # Write the data rows
        writer.writerows(csv_list)

    with open(measure_file_path, 'w') as f:
        for pipeline in pipeline_list:
            # file.write(f"A: {pipeline['A']}, B: {pipeline['B']}\n")
            f.write(pipeline['measure_name'])
            f.write(pipeline['measure_content'] + '\n')
            f.write("===========\n")
    if is_successrate:
        # import pdb; pdb.set_trace()
        keys_to_save = ['index','category','pipeline_url']
        csv_list = [{k: d[k] for k in keys_to_save} for d in success_rate_pipeline_list]
        excel_passrate_file_path = FOLDER + vendor_or_branch.capitalize() + "NightlySuccessRate" + ".csv"
        with open(excel_passrate_file_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys_to_save)
            # Write the data rows
            writer.writerows(csv_list)

        successrate_file_path = FOLDER + vendor_or_branch.capitalize() + "NightlySuccessRate" + ".txt"
        with open(successrate_file_path, 'w') as f:
            for pipeline in success_rate_pipeline_list:
                f.write(pipeline['measure_name'])
                f.write(pipeline['measure_content'] + '\n')
                f.write("===========\n")
    print("Save to files {}, {}, {} successfully!".format(excel_file_path, measure_file_path, successrate_file_path))
    return
         

def catetory_pipeline(pipeline_info):
    VENDOR_LIST = ['arista', 'celestica', 'dell', 'cisco', 'mellanox', 'nokia']
    BRANCH_LIST = ['master', '202012', '202205', '202305', 'internal']
    vendor_pipeline_dict = {}
    branch_pipeline_dict = {}
    pipeline_info_sorted = sorted(pipeline_info, key=lambda x: x['pipeline_name'])
    for pipeline in pipeline_info_sorted:
        pipeline_item_dict = pipeline.copy()
        successrate_item_dict = pipeline.copy()
        vendor = pipeline['vendor']
        branch = pipeline['branch']
        pipeline_name = pipeline['pipeline_name']
        if vendor in VENDOR_LIST:
            vendor_pipeline_dict[vendor] = {'pipeline_count': 0, 'pipeline_group': []} if vendor not in vendor_pipeline_dict else vendor_pipeline_dict[vendor]
            vendor_pipeline_dict[vendor]['pipeline_count'] = vendor_pipeline_dict[vendor]['pipeline_count'] + 1
            pipeline_item_dict['index'] = vendor_pipeline_dict[vendor]['pipeline_count']
            vendor_pipeline_dict[vendor]['pipeline_group'].append(pipeline_item_dict)
        for name in BRANCH_LIST:
            branch_pipeline_dict[name] = {'pipeline_count': 0, 'pipeline_group': [], 'successrate_group': []} if name not in branch_pipeline_dict else branch_pipeline_dict[name]
            if name in pipeline_name or name in branch.split('-')[-1]:
                branch_pipeline_dict[name]['pipeline_count'] = branch_pipeline_dict[name]['pipeline_count'] + 1
                successrate_item_dict['index'] = branch_pipeline_dict[name]['pipeline_count']
                branch_pipeline_dict[name]['pipeline_group'].append(successrate_item_dict)
                break

    for vendor in VENDOR_LIST:
        sorted_vendor_pipeline_list = sorted(vendor_pipeline_dict[vendor]['pipeline_group'], key=lambda x: x['pipeline_name'])
        vendor_pipeline_dict[vendor]['pipeline_group'] = []
        for pipeline in sorted_vendor_pipeline_list:
            vendor_pipeline_dict[vendor]['pipeline_group'].append(generate_pipeline_status_measure(pipeline, vendor))
    for branch in BRANCH_LIST:
        sorted_branch_pipeline_list = sorted(branch_pipeline_dict[branch]['pipeline_group'], key=lambda x: x['index'])
        branch_pipeline_dict[branch]['pipeline_group'] = []
        branch_pipeline_dict[branch]['successrate_group'] = []
        testbeds_set = set()
        successrate_count = 0
        for pipeline in sorted_branch_pipeline_list:
            branch_pipeline_dict[branch]['pipeline_group'].append(generate_pipeline_status_measure(pipeline, "key" + branch))
            for testbed in pipeline["testbed"].split(','):
                testbed = testbed.strip()
                if testbed in testbeds_set:
                    print("====Skip duplicated testbed {} for banch {} pipeline {}====".format(testbed, branch, pipeline['pipeline_name']))
                    continue
                else:
                    testbeds_set.add(testbed)
                    successrate_count += 1
                    branch_pipeline_dict[branch]['successrate_count'] = successrate_count
                    branch_pipeline_dict[branch]['successrate_group'].append(generate_successrate_measure(successrate_count, pipeline, branch, testbed))

    for vendor in VENDOR_LIST:
        save_to_files(vendor_pipeline_dict[vendor]['pipeline_group'], vendor)
    for branch in BRANCH_LIST:
        save_to_files(branch_pipeline_dict[branch]['pipeline_group'], branch, branch_pipeline_dict[branch]['successrate_group'], True)
    
    return

def main():
    # Get all the enabled nightly test pipelines.
    nightly_build_pipeline_info = get_nightly_build_definitions()
    
    print("nightly_build_pipeline_info: ")
    print(nightly_build_pipeline_info)
    catetory_pipeline(nightly_build_pipeline_info)


if __name__ == '__main__':
    main()

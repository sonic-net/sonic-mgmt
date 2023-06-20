'''
This script is used to collect all the nightly pipelines and category them into different files which are used for skywatch https://aka.ms/skywatch.
The output files are located in output folder.
Step 1: Create output folder
Step 2: python collect_powerbi_category.py
Step 3: Output files will be generaged in output folder
Step 4: Upload these files to https://microsoft.sharepoint.com/teams/Aznet/Engineering%20Q%20%20Z/Forms/AllItems.aspx?id=%2Fteams%2FAznet%2FEngineering%20Q%20%20Z%2FSONIC%2FTest%2Fnightly%5Fguard%2FPowerBI%2Foutput&viewid=7fb2dd98%2Da86b%2D47de%2D89ca%2D933d8e419fd6
Step 5: Run Program.cs with dotnet run, follow the instruction in Program.cs
Step 6: Refresh the PowerBI dataset and publish it to SONiC workspace

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---l         6/19/2023   5:20 PM           8367 AristaNightly.csv
-a---l         6/19/2023   5:20 PM          26831 AristaNightlyMeasure.txt
-a---l         6/19/2023   5:20 PM           1967 CelesticaNightly.csv
-a---l         6/19/2023   5:20 PM           6414 CelesticaNightlyMeasure.txt
-a---l         6/19/2023   5:20 PM           2229 CiscoNightly.csv
-a---l         6/19/2023   5:20 PM           7249 CiscoNightlyMeasure.txt
-a---l         6/19/2023   5:20 PM            826 DellNightly.csv
-a---l         6/19/2023   5:20 PM           2608 DellNightlyMeasure.txt
-a---l         6/19/2023   5:20 PM           3600 Internal-202012Nightly.csv
-a---l         6/19/2023   5:20 PM          11745 Internal-202012NightlyMeasure.txt
-a---l         6/19/2023   5:20 PM           4820 Internal-202012NightlySuccessRate.txt
-a---l         6/19/2023   5:20 PM           8087 Internal-202205Nightly.csv
-a---l         6/19/2023   5:20 PM          26073 Internal-202205NightlyMeasure.txt
-a---l         6/19/2023   5:20 PM          10698 Internal-202205NightlySuccessRate.txt
-a---l         6/19/2023   5:20 PM           2436 InternalNightly.csv
-a---l         6/19/2023   5:20 PM           7815 InternalNightlyMeasure.txt
-a---l         6/19/2023   5:20 PM           3233 InternalNightlySuccessRate.txt
-a---l         6/19/2023   5:20 PM           2129 MasterNightly.csv
-a---l         6/19/2023   5:20 PM           6843 MasterNightlyMeasure.txt
-a---l         6/19/2023   5:20 PM           2821 MasterNightlySuccessRate.txt
-a---l         6/19/2023   5:20 PM           3488 MellanoxNightly.csv
-a---l         6/19/2023   5:20 PM          11118 MellanoxNightlyMeasure.txt
-a---l         6/19/2023   5:20 PM            542 NokiaNightly.csv
-a---l         6/19/2023   5:20 PM           1744 NokiaNightlyMeasure.txt
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
        nightly_pipelines = {}
        enabled = False
        nightly = False

        if 'queueStatus' in build and build['queueStatus'] == 'enabled':
            enabled = True
        if 'path' in build and build['path'].startswith('\\Nightly') and not build['path'].startswith('\\Nightly-Hawk') and not '\\Disabled' in build['path']:
            nightly = True
        if not enabled or not nightly:
            continue
        if '-t2-' in build['name'].lower():
            print("====Skip T2 pipeline so far. {}".format(build['name']))
            continue
        if '\\rdma' in build['path'].lower() or '\\wan' in build['path'].lower() or '\\intel' in build['path'].lower():
            print("====Skip RDMA/WAN/Intel pipeline so far. {}".format(build['name']))
            continue
            
        nightly_pipelines['pipeline_name'] = build['name']
        nightly_pipelines['pipeline_url'] = build['_links']['web']['href']
        nightly_pipelines['pipeline_id'] = build['id']
        vendor = build['path'].split('\\')[-1]
        nightly_pipelines['vender'] = vendor
        build_detail = requests.get(build['url'], auth=AUTH).json()
        branch = build_detail['repository']['defaultBranch'].lstrip('refs/heads/')
        nightly_pipelines['branch'] = branch

        repo_id = build_detail['repository']['id']
        yamlFileName = build_detail['process']['yamlFilename']
        print("yamlFileName: {}".format(yamlFileName))
        pipeline_yaml = yaml.safe_load(get_git_item(repo_id, branch, yamlFileName))
        yaml_result = extract_pipeline_info(pipeline_yaml)

        nightly_pipelines['testbed'] = yaml_result['testbed']
        nightly_pipelines['branch'] = yaml_result['branch'] if yaml_result['branch'] else branch
        if yaml_result['branch'] != branch:
            print("!!!!!!!!!branch not match {} : {} != {}".format(build['name'], yaml_result['branch'], branch))
        if not yaml_result['testbed']:
            print("!!!!!!!!!testbed not found {}".format(build['name']))
            continue
        print("{}\t{}\t{}\t{}\t{}".format(build['name'], build['id'], nightly_pipelines['branch'], vendor, nightly_pipelines['testbed']))

        nightly_pipeline_list.append(nightly_pipelines)

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


def generate_measure(index, pipeline_info, vender, is_successrate=False):
    """Generate measure name for each pipeline.

    Args:
        pipeline_info (dict): Dict of parsed nightly test runs for all testbeds.
        vender (str): Vender name.

    Returns:
        list: List of pipeline info with measure name.
    """
    pipeline_dict = {}
    pipeline_dict = pipeline_info.copy()
    pipeline_dict['index'] = index

    if is_successrate:
        measure_name = str(index) + " " + pipeline_dict["testbed"] + "_" + vender
        pipeline_dict["table"] = "SONiCKusto"
        pipeline_dict["measure_name"] = measure_name
        if vender == 'master':
            branch_name = "master"
        elif vender == 'internal':
            branch_name = 'internal'
        elif vender == '202012':
            branch_name = '20201231'
        elif vender == '202205':
            branch_name = '20220531'
   
        pipeline_dict["measure_content"] = ''' 
CALCULATE(
    MAX(SONiCKusto[SuccessRate]),
    SONiCKusto[TestbedName] = "{}",
    SONiCKusto[BranchName] = "{}"
)'''.format(pipeline_info['testbed'], branch_name)
    else:
        measure_name = str(index) + " " + pipeline_dict["pipeline_name"] + "_" + vender
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

def save_to_files(pipeline_list, vender_or_branch, success_rate_pipeline_list=None, is_successrate=False):
    keys_to_save = ['index','pipeline_name','pipeline_url']
    # df = pd.DataFrame([{k: d[k] for k in keys_to_save} for d in pipeline_list])
    csv_list = [{k: d[k] for k in keys_to_save} for d in pipeline_list]
    vender_list = ['arista', 'celestica', 'dell', 'cisco', 'mellanox', 'nokia']
    excel_file_path = FOLDER + vender_or_branch.capitalize() + "Nightly" + ".csv"
    
    measrue_file_path = FOLDER + vender_or_branch.capitalize() + "NightlyMeasure" + ".txt"
    successrate_file_path = None

    with open(excel_file_path, 'w', newline='') as csvfile:
      writer = csv.DictWriter(csvfile, fieldnames=keys_to_save)
      # Write the data rows
      writer.writerows(csv_list)

    with open(measrue_file_path, 'w') as f:
        for pipeline in pipeline_list:
            # file.write(f"A: {pipeline['A']}, B: {pipeline['B']}\n")
            f.write(pipeline['measure_name'])
            f.write(pipeline['measure_content'] + '\n')
            f.write("===========\n")
    if is_successrate:
        successrate_file_path = FOLDER + vender_or_branch.capitalize() + "NightlySuccessRate" + ".txt"
        with open(successrate_file_path, 'w') as f:
            for pipeline in success_rate_pipeline_list:
                f.write(pipeline['measure_name'])
                f.write(pipeline['measure_content'] + '\n')
                f.write("===========\n")
    print("Save to files {}, {}, {} successfully!".format(excel_file_path, measrue_file_path, successrate_file_path))
    return
         

def catetory_pipeline(pipeline_info):
    arista_pipeline = []
    celestica_pipeline = []
    cisco_pipeline = []
    dell_pipeline = []
    mellanox_pipeline = []
    nokia_pipeline = []

    master_pipeline = []
    internal_pipeline = []
    internal_202012_pipeline = []
    internal_202205_pipeline = []

    master_pass_rate_pipeline = []
    internal_pass_rate_pipeline = []
    internal_202012_pass_rate_pipeline = []
    internal_202205_pass_rate_pipeline = []

    arista_count = 0
    celestica_count = 0
    cisco_count = 0
    dell_count = 0
    mellanox_count = 0
    nokia_count = 0

    master_count = 0
    internal_count = 0
    internal_202012_count = 0
    internal_202205_count = 0

    master_pass_rate_count = 0
    internal_pass_rate_count = 0
    internal_202012_pass_rate_count = 0
    internal_202205_pass_rate_count = 0

    for pipeline in pipeline_info:
        pipeline_dict = {}
        if pipeline['vender'] == 'arista':
            arista_count += 1
            pipeline_dict = generate_measure(arista_count, pipeline, 'arista')
            arista_pipeline.append(pipeline_dict)
        elif pipeline['vender'] == 'celestica':
            celestica_count += 1
            pipeline_dict = generate_measure(celestica_count, pipeline, 'celestica')
            celestica_pipeline.append(pipeline_dict)
        elif pipeline['vender'] == 'cisco':
            cisco_count += 1
            pipeline_dict = generate_measure(cisco_count, pipeline, 'cisco')
            cisco_pipeline.append(pipeline_dict)
        elif pipeline['vender'] == 'dell':
            dell_count += 1
            pipeline_dict = generate_measure(dell_count, pipeline, 'dell')
            dell_pipeline.append(pipeline_dict)
        elif pipeline['vender'] == 'mellanox':
            mellanox_count += 1
            pipeline_dict = generate_measure(mellanox_count, pipeline, 'mellanox')
            mellanox_pipeline.append(pipeline_dict)
        elif pipeline['vender'] == 'nokia':
            nokia_count += 1
            pipeline_dict = generate_measure(nokia_count, pipeline, 'nokia')
            nokia_pipeline.append(pipeline_dict)
    # import pdb; pdb.set_trace()
    sortedd_pipeline_list = sorted(pipeline_info, key=lambda x: x['vender'])
    for pipeline in sortedd_pipeline_list:
        pipeline_dict = {}
        name = pipeline['pipeline_name']
        if 'azd' in name or '3164' in name or 'e1031' in name or 'pikez' in name:
            print("====Skip azd/3164/e1031/pikez pipelines {}".format(pipeline['pipeline_name']))
            continue
            
        if 'master' in pipeline['pipeline_name']:
            master_count += 1
            pipeline_dict = generate_measure(master_count, pipeline, 'keymaster')
            master_pipeline.append(pipeline_dict)
            master_pass_rate_count += 1
            pipeline_dict = generate_measure(master_pass_rate_count, pipeline, 'master', True)
            master_pass_rate_pipeline.append(pipeline_dict)
        elif 'internal' in pipeline['pipeline_name']:
            internal_count += 1
            pipeline_dict = generate_measure(internal_count, pipeline, 'keyinternal')
            internal_pipeline.append(pipeline_dict)
            internal_pass_rate_count += 1
            pipeline_dict = generate_measure(internal_pass_rate_count, pipeline, 'internal', True)
            internal_pass_rate_pipeline.append(pipeline_dict)
        elif pipeline['branch'] == 'internal-202012':
            internal_202012_count += 1
            pipeline_dict = generate_measure(internal_202012_count, pipeline, 'key202012')
            internal_202012_pipeline.append(pipeline_dict)
            internal_202012_pass_rate_count += 1
            pipeline_dict = generate_measure(internal_202012_pass_rate_count, pipeline, '202012', True)
            internal_202012_pass_rate_pipeline.append(pipeline_dict)
        elif pipeline['branch'] == 'internal-202205':
            internal_202205_count += 1
            pipeline_dict = generate_measure(internal_202205_count, pipeline, 'key202205')
            internal_202205_pipeline.append(pipeline_dict)
            internal_202205_pass_rate_count += 1
            pipeline_dict = generate_measure(internal_202205_pass_rate_count, pipeline, '202205', True)
            internal_202205_pass_rate_pipeline.append(pipeline_dict)  
    save_to_files(arista_pipeline, 'arista')
    save_to_files(celestica_pipeline, 'celestica')
    save_to_files(cisco_pipeline, 'cisco')
    save_to_files(dell_pipeline, 'dell')
    save_to_files(mellanox_pipeline, 'mellanox')
    save_to_files(nokia_pipeline, 'nokia')

    save_to_files(master_pipeline, 'master', master_pass_rate_pipeline, True)
    save_to_files(internal_pipeline, 'internal', internal_pass_rate_pipeline, True)
    save_to_files(internal_202012_pipeline, 'internal-202012', internal_202012_pass_rate_pipeline, True)
    save_to_files(internal_202205_pipeline, 'internal-202205', internal_202205_pass_rate_pipeline, True)


    print_list = []
    print_list = arista_pipeline + celestica_pipeline + cisco_pipeline + dell_pipeline + mellanox_pipeline + nokia_pipeline
    print('******Vendor*****\n')
    for pipeline in print_list:
        print(json.dumps(pipeline, indent=4))

    print_list = []
    print_list = master_pipeline + internal_pipeline + internal_202012_pipeline + internal_202205_pipeline
    print('******Branch*****\n')
    for pipeline in print_list:
        print(json.dumps(pipeline, indent=4))

    print_list = []
    print_list = master_pass_rate_pipeline + internal_pass_rate_pipeline + internal_202012_pass_rate_pipeline + internal_202205_pass_rate_pipeline
    print('******Pass Rate*****\n')
    for pipeline in print_list:
        print(json.dumps(pipeline, indent=4))
    
            
def main():
    # Get all the enabled nightly test pipelines.
    nightly_build_pipeline_info = get_nightly_build_definitions()
    
    print("nightly_build_pipeline_info: ")
    print(nightly_build_pipeline_info)
    catetory_pipeline(nightly_build_pipeline_info)


if __name__ == '__main__':
    main()

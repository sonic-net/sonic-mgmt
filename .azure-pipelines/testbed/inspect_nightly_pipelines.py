from __future__ import print_function

import json
import os
import yaml
import requests

from datetime import datetime
from datetime import timedelta

from crontab import CronTab

BASE_URL = 'https://dev.azure.com/mssonic/internal/_apis'
TOKEN = os.environ.get('AZURE_DEVOPS_MSSONIC_TOKEN')
if not TOKEN:
    raise Exception('Must export environment variable AZURE_DEVOPS_MSSONIC_TOKEN')
AUTH = ('', TOKEN)

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

    nightly_pipelines = []
    for build in build_definitions:
        enabled = False
        nightly = False

        if 'queueStatus' in build and build['queueStatus'] == 'enabled':
            enabled = True
        if 'path' in build and build['path'].startswith('\\Nightly'):
            nightly = True

        if all([enabled, nightly]):
            nightly_pipelines.append(build)

    return nightly_pipelines


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
        'crons': []
    }
    if 'parameters' in pipeline:
        for parameter in pipeline['parameters']:
            if 'name' in parameter and parameter['name'] == 'TESTBED_NAME':
                res['testbed'] = parameter.get('default', '')
                break
    if 'schedules' in pipeline:
        for schedule in pipeline['schedules']:
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


def main():
    # Get all the enabled nightly test pipelines.
    nightly_build_definitions = get_nightly_build_definitions()

    # Extract schedule information of the pipelines from their associated yaml file.
    testbeds_crons = parse_testbeds_crons(nightly_build_definitions)

    # Figure out expected runs of all the pipelines in calendar day of yesterday
    begin, end = get_yesterday_time_range()
    expected_runs = []
    for testbed in testbeds_crons:
        timestamps = []
        crons = testbeds_crons[testbed]['crons']
        for cron in crons:
            timestamps = get_yesterday_schedules(cron, begin, end)
            for timestamp in timestamps:
                expected_runs.append({
                    'testbed': testbed,
                    'timestamp': str(timestamp)
                })

    # Output the parsed content
    print(json.dumps(expected_runs))


if __name__ == '__main__':
    main()

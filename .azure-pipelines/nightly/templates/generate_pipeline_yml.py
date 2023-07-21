"""
Pipeline yaml soure data is to get from the following workbook:
https://microsoft.sharepoint.com/:x:/r/teams/Aznet/_layouts/15/Doc.aspx?sourcedoc=%7B2CACD877-11BE-4C11-9DAF-A90643F5B746%7D&file=nightly_pipelines_data_source.xlsx&action=default&mobileredirect=true&share=IQF32KwsvhERTJ2vqQZD9bdGAeCQS1UQj9cpxbrjSJQAFZw

Generate nightly pipeline yaml file steps:
1. Fill the workbook above accordingly, for example, fill the TESTBED_NAME, TESTBED_SPECIFIC, SKIP_SCRIPTS, cron column, etc.
2. Make sure the schedule is correct, schedule colomn is from Sun-0 to Sat-6.
3. Copy the rows you want to adjust to pipeline_data.csv.
4. Go into sonic-mgmt docker container: docker exec -it sonic-mgmt bash; pip3 install pandas.
5. cd .azure-pipelines/nightly/templates; python3 generate_pipeline_yml.py
"""
import json
import pandas as pd


def generate_pipeline_yaml(yaml_file_info):
    print("yaml_file_info:{}".format(json.dumps(yaml_file_info, indent=4)))
    HEAD_PATTERN = '''name: NightlyTest_$(Build.DefinitionName)_$(SourceBranchName)_$(Build.BuildId)_$(Date:yyyyMMdd)$(Rev:.r)

trigger: none
pr: none
'''
    METADATA_PATTERN = '''
resources:
  repositories:
  - repository: https://mssonic@dev.azure.com/mssonic/internal/_git/sonic-metadata
    type: git
    name: sonic-metadata
    ref: master
'''
    
    for branch in yaml_file_info:
        file_content = ''
        file_content += HEAD_PATTERN

        cron = yaml_file_info[branch]['cron']
        branches = yaml_file_info[branch]['branches']
        TESTBED_NAME = yaml_file_info[branch]['TESTBED_NAME']
        IMAGE_URL = yaml_file_info[branch]['IMAGE_URL']
        PY_SAITHRIFT_URL = yaml_file_info[branch]['PY_SAITHRIFT_URL']
        TESTBED_SPECIFIC = yaml_file_info[branch]['TESTBED_SPECIFIC']
        if '202012' in branches or 'metadata-scripts' in TESTBED_SPECIFIC:
            file_content += METADATA_PATTERN

        COMMON_PATTERN = '''
schedules:
  - cron: {}
    displayName: Nightly Scheduler
    branches:
      include:
        - {}
    always: true

variables:
  - group: SONIC_IMAGE_URLS
  - group: SAITHRIFT_URLS

parameters:
  - name: TESTBED_NAME
    type: string
    default: {}
    displayName: "Testbed Name"

  # Upgrade parameters
  - name: IMAGE_URL
    type: string
    default: $({})
    displayName: "Image URL"

  # Test Parameters
  - name: PY_SAITHRIFT_URL
    type: string
    default: $({})
    displayName: "py_saithrift URL"
'''.format(cron, branches, TESTBED_NAME, IMAGE_URL, PY_SAITHRIFT_URL)

        file_content += COMMON_PATTERN
        SKIP_SCRIPTS = yaml_file_info[branch]['SKIP_SCRIPTS']
        NIGHTLY_TEST_TIMEOUT = yaml_file_info[branch]['NIGHTLY_TEST_TIMEOUT']
        AGENT_POOL = yaml_file_info[branch]['AGENT_POOL']
        CROSS_BRANCH_BASE_URL = yaml_file_info[branch]['CROSS_BRANCH_BASE_URL']
        TEST_IN_BRANCH_UPGRADE = yaml_file_info[branch]['TEST_IN_BRANCH_UPGRADE']
        ALWAYS_POWER_CYCLE_DUTS = yaml_file_info[branch]['ALWAYS_POWER_CYCLE_DUTS']
        ENABLE_DATAACL = yaml_file_info[branch]['ENABLE_DATAACL']
        SKIP_TEST_RESULTS_UPLOADING = yaml_file_info[branch]['SKIP_TEST_RESULTS_UPLOADING']
        PREV_IMAGE_URL = yaml_file_info[branch]['PREV_IMAGE_URL']

        STATE_PATTERN = '''
stages:
  - template: ../templates/nightly_test.yml
    parameters:
      TESTBED_NAME: ${{ parameters.TESTBED_NAME }}
      IMAGE_URL: ${{ parameters.IMAGE_URL }}
      PY_SAITHRIFT_URL: ${{ parameters.PY_SAITHRIFT_URL }}'''

        if ALWAYS_POWER_CYCLE_DUTS == 'TRUE':
            POWER_CYCLE_PATTERN = '''
  - name: ALWAYS_POWER_CYCLE_DUTS
    type: boolean
    default: true
    displayName: "Always power cycle DUTs"\n'''
            file_content += POWER_CYCLE_PATTERN
            STATE_PATTERN += "\n      ALWAYS_POWER_CYCLE_DUTS: ${{ parameters.ALWAYS_POWER_CYCLE_DUTS }}"

        if ENABLE_DATAACL == 'FALSE':
            DATAACL_PATTERN = '''
  # Deploy parameters
  - name: ENABLE_DATAACL
    type: boolean
    default: false\n'''
            file_content += DATAACL_PATTERN
            STATE_PATTERN += "\n      ENABLE_DATAACL: ${{ parameters.ENABLE_DATAACL }}"

        if TESTBED_SPECIFIC:
            SPECIFIC_PATTERN = '''
  # Testbed specific, to skip and/or include directories
  - name: TESTBED_SPECIFIC
    type: string
    default: '{}'
    displayName: Testbed specific\n'''.format(TESTBED_SPECIFIC)
            file_content += SPECIFIC_PATTERN
            STATE_PATTERN += "\n      TESTBED_SPECIFIC: ${{ parameters.TESTBED_SPECIFIC }}"

        if SKIP_SCRIPTS:
            SKIP_SCRIPTS_PATTERN = '''
  # Custom skip scripts
  - name: SKIP_SCRIPTS
    type: string
    default: "{}"
    displayName: "Skip Scripts"\n'''.format(SKIP_SCRIPTS)
            file_content += SKIP_SCRIPTS_PATTERN
            STATE_PATTERN += "\n      SKIP_SCRIPTS: ${{ parameters.SKIP_SCRIPTS }}"

        if CROSS_BRANCH_BASE_URL:
            CROSSH_BRANCH_PATTERN = '''
  - name: CROSS_BRANCH_BASE_URL
    type: string
    default: $({})
    displayName: "Cross-branch base-image URL"

  - name: TEST_CROSS_BRANCH_UPGRADE
    default: true
    type: boolean\n'''.format(CROSS_BRANCH_BASE_URL)
            file_content += CROSSH_BRANCH_PATTERN
            STATE_PATTERN += '''
      CROSS_BRANCH_BASE_URL: ${{ parameters.CROSS_BRANCH_BASE_URL }}
      TEST_CROSS_BRANCH_UPGRADE: ${{ parameters.TEST_CROSS_BRANCH_UPGRADE }}'''

        if TEST_IN_BRANCH_UPGRADE == 'TRUE':
            TEST_IN_BRANCH_UPGRADE_PATTERN = '''
  - name: TEST_IN_BRANCH_UPGRADE
    default: true
    type: boolean\n'''
            file_content += TEST_IN_BRANCH_UPGRADE_PATTERN
            STATE_PATTERN += '''\n      TEST_IN_BRANCH_UPGRADE: ${{ parameters.TEST_IN_BRANCH_UPGRADE }}'''

        if NIGHTLY_TEST_TIMEOUT:
            TIME_OUT_PATTERN = '''
  # Test timeout
  - name: NIGHTLY_TEST_TIMEOUT
    type: number
    default: {}\n'''.format(NIGHTLY_TEST_TIMEOUT)
            file_content += TIME_OUT_PATTERN
            STATE_PATTERN += "\n      NIGHTLY_TEST_TIMEOUT: ${{ parameters.NIGHTLY_TEST_TIMEOUT }}"

        if AGENT_POOL:
            AGENT_PATTERN = '''
  - name: AGENT_POOL
    type: string
    default: {}
    displayName: "Agent pool"\n'''.format(AGENT_POOL)
            file_content += AGENT_PATTERN
            STATE_PATTERN += "\n      AGENT_POOL: ${{ parameters.AGENT_POOL }}"

        if SKIP_TEST_RESULTS_UPLOADING == 'FALSE':
            SKIP_UPLOADING_PATTERN = '''
  - name: SKIP_TEST_RESULTS_UPLOADING
    type: boolean
    default: false
    displayName: "Skip uploading test results to Kusto"\n'''
            file_content += SKIP_UPLOADING_PATTERN
            STATE_PATTERN += "\n      SKIP_TEST_RESULTS_UPLOADING: ${{ parameters.SKIP_TEST_RESULTS_UPLOADING }}"

        if PREV_IMAGE_URL:
            PREV_IMAGE_URL_PATTERN = '''
  - name: PREV_IMAGE_URL
    type: string
    default: $({})
    displayName: "Previous Image URL"\n'''.format(PREV_IMAGE_URL)
            file_content += PREV_IMAGE_URL_PATTERN
            STATE_PATTERN += '''
      PREV_IMAGE_URL: ${{ parameters.PREV_IMAGE_URL }}'''

        file_content += STATE_PATTERN + "\n"
        vender = yaml_file_info[branch]['vendor']
        file_name = yaml_file_info[branch]['file_name']
        file_path = '../' + vender + '/' + file_name
        with open(file_path, "w") as f:
            f.write(file_content)
        print("Generate {} successfully!".format(file_path))

def parse_csv_file():
    # Read CSV file into DataFrame
    df = pd.read_csv('pipeline_data.csv', dtype='str', keep_default_na=False, delimiter='\t')
    return df


def generate_yaml_files(data_df):
    keys = data_df.keys()

    for index, row in data_df.iterrows():
        yaml_file_info = {}
        TESTBED_SPECIFIC = ''
        SKIP_SCRIPTS = ''
        AGENT_POOL = ''
        NIGHTLY_TEST_TIMEOUT = ''
        CROSS_BRANCH_BASE_URL = ''
        TEST_IN_BRANCH_UPGRADE = ''
        ALWAYS_POWER_CYCLE_DUTS = ''
        ENABLE_DATAACL = ''
        SKIP_TEST_RESULTS_UPLOADING = ''
        PREV_IMAGE_URL = ''
        for day_index in range(3, 10):
            day_key = keys[day_index]
            if row[day_key] != '':
                branch = row[day_key]
                day_schedule = day_key.split('-')[1]
                yaml_file_info[branch] = yaml_file_info.get(branch, {'cron_list':[]})
                yaml_file_info[branch].get('cron_list', []).extend([day_schedule])
        
        for key in keys:
            if key.lower() == "vendor":
                vendor = row[key]
            if key.upper() == "TESTBED_NAME":
                TESTBED_NAME = row[key]
            if key.lower() == "pipeline_name":
                file_name_prefix = row[key]
            if key.upper() == "TESTBED_SPECIFIC":
                TESTBED_SPECIFIC = row[key]
                if TESTBED_SPECIFIC and TESTBED_SPECIFIC[-1] == '\'':
                    TESTBED_SPECIFIC = TESTBED_SPECIFIC[:-1]
            if key.lower() == "cron":
                cron = row[key]
            if key.upper() == "NIGHTLY_TEST_TIMEOUT":
                NIGHTLY_TEST_TIMEOUT = row[key]
            if key.upper() == "SKIP_SCRIPTS":
                SKIP_SCRIPTS = row[key]
                if SKIP_SCRIPTS:
                    SKIP_SCRIPTS = SKIP_SCRIPTS.strip("\"")
            if key.upper() == "AGENT_POOL":
                AGENT_POOL = row[key]
            if key.upper() == "CROSS_BRANCH_BASE_URL":
                CROSS_BRANCH_BASE_URL = row[key]
            if key.upper() == "TEST_IN_BRANCH_UPGRADE":
                TEST_IN_BRANCH_UPGRADE = row[key].upper()
            if key.upper() == "ALWAYS_POWER_CYCLE_DUTS":
                ALWAYS_POWER_CYCLE_DUTS = row[key].upper()
            if key.upper() == "ENABLE_DATAACL":
                ENABLE_DATAACL = row[key].upper()
            if key.upper() == "SKIP_TEST_RESULTS_UPLOADING":
                SKIP_TEST_RESULTS_UPLOADING = row[key].upper()
            if key.upper() == "PREV_IMAGE_URL":
                PREV_IMAGE_URL = row[key]

        for branch in yaml_file_info:
            branch_alias = branch
            if branch == '201911':
                yaml_file_info[branch]['branches'] = 'internal-202012'
            elif '202012' in branch:
                branch_alias = '202012'
                yaml_file_info[branch]['branches'] = 'internal-202012'
            elif '202205' in branch:
                branch_alias = '202205'
                yaml_file_info[branch]['branches'] = 'internal-202205'
            else:
                yaml_file_info[branch]['branches'] = 'internal'

            yaml_file_info[branch]['vendor'] = vendor.lower()
            yaml_file_info[branch]['file_name'] = file_name_prefix + '.' + branch_alias + '.yml'
            yaml_file_info[branch]['cron'] = "\"" + cron + " * * "+ ','.join(yaml_file_info[branch]['cron_list']) + "\""
            yaml_file_info[branch]['TESTBED_NAME'] = TESTBED_NAME
            yaml_file_info[branch]['TESTBED_SPECIFIC'] = TESTBED_SPECIFIC
            yaml_file_info[branch]['NIGHTLY_TEST_TIMEOUT'] = NIGHTLY_TEST_TIMEOUT
            yaml_file_info[branch]['SKIP_SCRIPTS'] = SKIP_SCRIPTS
            yaml_file_info[branch]['AGENT_POOL'] = AGENT_POOL
            yaml_file_info[branch]['CROSS_BRANCH_BASE_URL'] = CROSS_BRANCH_BASE_URL
            yaml_file_info[branch]['TEST_IN_BRANCH_UPGRADE'] = TEST_IN_BRANCH_UPGRADE
            yaml_file_info[branch]['ALWAYS_POWER_CYCLE_DUTS'] = ALWAYS_POWER_CYCLE_DUTS
            yaml_file_info[branch]['ENABLE_DATAACL'] = ENABLE_DATAACL
            yaml_file_info[branch]['SKIP_TEST_RESULTS_UPLOADING'] = SKIP_TEST_RESULTS_UPLOADING
            yaml_file_info[branch]['PREV_IMAGE_URL'] = PREV_IMAGE_URL

            if 'bjw' in AGENT_POOL:
                IMAGE_URL_PREFIX = "BJW_IMAGE_"
                SAITHRIFT_URL_PREFIX = "BJW_SAITHRIFT_"
            else:
                IMAGE_URL_PREFIX = "IMAGE_"
                SAITHRIFT_URL_PREFIX = "SAITHRIFT_"

            if vendor.lower() == "mellanox":
                IMAGE_URL_PREFIX += "MLNX_"
                SAITHRIFT_URL_PREFIX +=  "MLNX_"
            elif vendor.lower() == "arista":
                IMAGE_URL_PREFIX += "BRCM_ABOOT_"
                SAITHRIFT_URL_PREFIX +=  "BRCM_"
            elif vendor.lower() == "dell" or vendor.lower() == "celestica":
                IMAGE_URL_PREFIX += "BRCM_"
                SAITHRIFT_URL_PREFIX += "BRCM_"
            elif vendor.lower() == "nokia":
                IMAGE_URL_PREFIX += "MARVELL_"
                SAITHRIFT_URL_PREFIX +=  "MARVELL_"
            if branch == 'master':
                BRANCH = 'PUBLIC'
                SAI_BRANCH = BRANCH
            elif branch.upper() == '202012-SLIM':
                BRANCH = '202012_SLIM'
                SAI_BRANCH = '202012'
            elif branch.upper() == '202205-SLIM':
                BRANCH = '202205_SLIM'
                SAI_BRANCH = '202205'                
            else:
                BRANCH = branch.upper()
                SAI_BRANCH = BRANCH
            yaml_file_info[branch]['IMAGE_URL'] = IMAGE_URL_PREFIX + BRANCH
            yaml_file_info[branch]['PY_SAITHRIFT_URL'] = SAITHRIFT_URL_PREFIX + SAI_BRANCH
            
        # import pdb; pdb.set_trace()
        generate_pipeline_yaml(yaml_file_info)

def main():
    data_df = parse_csv_file()
    generate_yaml_files(data_df)


if __name__ == '__main__':
    main()

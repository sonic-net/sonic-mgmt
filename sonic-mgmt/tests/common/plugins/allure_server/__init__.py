import time
import logging
import os
import requests
import base64
import re
import subprocess

from tests.common.helpers.constants import RANDOM_SEED


logger = logging.getLogger()

FileNotFoundError = IOError
ALLURE_REPORT_URL = 'allure_report_url'


def pytest_addoption(parser):
    """
    Parse pytest options
    :param parser: pytest buildin
    """
    parser.addoption('--allure_server_addr', action='store', default=None, help='Allure server address: IP/domain name')
    parser.addoption('--allure_server_port', action='store', default=None, help='Allure server port')
    parser.addoption('--allure_server_project_id', action='store', default=None, help='Allure server project ID')


def pytest_sessionfinish(session, exitstatus):
    """
    Pytest hook which are executed after all tests before exist from program
    :param session: pytest buildin
    :param exitstatus: pytest buildin
    """
    if not session.config.getoption("--collectonly"):
        allure_server_addr = session.config.option.allure_server_addr
        allure_server_port = session.config.option.allure_server_port
        allure_server_project_id = session.config.option.allure_server_project_id

        if allure_server_addr:
            allure_report_dir = session.config.option.allure_report_dir
            if allure_report_dir:
                session_info_dict = {}
                try:
                    session_info_dict = get_setup_session_info(session)
                except Exception as err:
                    logger.warning('Can not get session info for Allure report. Error: {}'.format(err))

                if session_info_dict:
                    export_session_info_to_allure(session_info_dict, allure_report_dir)

                try:
                    allure_server_obj = AllureServer(allure_server_addr, allure_server_port, allure_report_dir, allure_server_project_id)
                    report_url = allure_server_obj.generate_allure_report()
                    session.config.cache.set(ALLURE_REPORT_URL, report_url)
                except Exception as err:
                    logger.error('Failed to upload allure report to server. Allure report not available. '
                                 '\nError: {}'.format(err))
            else:
                logger.error('PyTest argument "--alluredir" not provided. Impossible to generate Allure report')


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    report_url = config.cache.get(ALLURE_REPORT_URL, None)
    if report_url:
        logger.info('Allure report URL: {}'.format(report_url))
    else:
        logger.info('Can not get Allure report URL. Please check logs')


def get_setup_session_info(session):
    ansible_dir = get_ansible_path(session)
    testbed = session.config.option.testbed

    os.chdir(ansible_dir)

    cmd = "ansible -m command -i inventory {} -a 'show version'".format(testbed)
    output = subprocess.check_output(cmd, shell=True).decode('utf-8')

    version = re.compile(r"sonic software version: +([^\s]+)\s", re.IGNORECASE)
    platform = re.compile(r"platform: +([^\s]+)\s", re.IGNORECASE)
    hwsku = re.compile(r"hwsku: +([^\s]+)\s", re.IGNORECASE)
    asic = re.compile(r"asic: +([^\s]+)\s", re.IGNORECASE)

    random_seed = session.config.cache.get(RANDOM_SEED, None)

    result = {
        "Version": version.findall(output)[0] if version.search(output) else "",
        "Platform": platform.findall(output)[0] if platform.search(output) else "",
        "HwSKU": hwsku.findall(output)[0] if hwsku.search(output) else "",
        "ASIC": asic.findall(output)[0] if asic.search(output) else "",
        "Random_seed": random_seed
    }

    return result



def export_session_info_to_allure(session_info_dict, allure_report_dir):
    allure_env_file_name = 'environment.properties'
    allure_env_file_path = os.path.join(allure_report_dir, allure_env_file_name)
    with open(allure_env_file_path, 'w') as env_file_obj:
        for item, value in session_info_dict.items():
            env_file_obj.write('{}={}\n'.format(item, value))


def get_ansible_path(session):
    sonic_mgmt_dir_path = session.fspath.dirname
    ansible_dir = os.path.join(sonic_mgmt_dir_path, 'ansible')

    if not os.path.exists(ansible_dir):
        raise FileNotFoundError('Ansible path "{}" does not exist'.format(ansible_dir))

    return ansible_dir


def get_time_stamp_str():
    """
    This method return string with current time
    :return: string, example: 16063138520755782
    """
    current_time = time.time()
    current_time_without_dot = str(current_time).replace('.', '')
    return current_time_without_dot


class AllureServer:
    def __init__(self, allure_server_ip, allure_server_port, allure_report_dir, allure_server_project_id=None):
        self.allure_report_dir = allure_report_dir

        if allure_server_port:
            self.base_url = "http://{}:{}/allure-docker-service".format(allure_server_ip, allure_server_port)
        else:
            self.base_url = "http://{}/allure-docker-service".format(allure_server_ip)
        self.project_id = str(allure_server_project_id) if allure_server_project_id else get_time_stamp_str()
        self.http_headers = {"Content-type": "application/json"}

    def generate_allure_report(self):
        """
        This method creates new project(if need) on allure server, uploads test results to server and generates report
        """
        self.create_project_on_allure_server()
        self.upload_results_to_allure_server()
        report_url = self.generate_report_on_allure_server()
        self.clean_results_on_allure_server()
        return report_url

    def create_project_on_allure_server(self):
        """
        This method creates new project(if need) on allure server
        """
        data = {'id': self.project_id}
        url = self.base_url + '/projects'
        logger.info("Base url: {}".format(url))
        get_project_res = requests.get(url + "/" + self.project_id)
        if get_project_res.status_code == 404:
            logger.info("Creating project {} on allure server".format(self.project_id))
            response = requests.post(url, json=data, headers=self.http_headers)
            if not response.ok:
                logger.error("Failed to create project on allure server, error: {}".format(response.content))
        elif get_project_res.status_code == 200:
            logger.info("Allure project {} already exist on server. No need to create project".format(self.project_id))
        else:
            logger.info("Unknown error, status: {}".format(get_project_res.status_code))


    def upload_results_to_allure_server(self):
        """
        This method uploads files from allure results folder to allure server
        """
        data = {"results": self.get_allure_files_content()}
        params = {"project_id": self.project_id}
        url = self.base_url + "/send-results"

        logger.info("Sending allure results to allure server")
        response = requests.post(url, params=params, json=data, headers=self.http_headers)
        if not response.ok:
            logger.error("Failed to upload results to allure server, error: {}".format(response.content))

    def get_allure_files_content(self):
        """
        This method creates a list all files under allure report folder
        :return: list with allure folder content, example
        [
            {
                'file_name': 'xyz',
                'content_base64': 'xyz'
            },
            ...
        ]
        """
        files = os.listdir(self.allure_report_dir)
        results = []

        for file in files:
            result = {}
            file_path = self.allure_report_dir + "/" + file
            if os.path.isfile(file_path):
                try:
                    with open(file_path, "rb") as f:
                        content = f.read()
                        if content.strip():
                            b64_content = base64.b64encode(content)
                            result["file_name"] = file
                            result["content_base64"] = b64_content.decode("UTF-8")
                            results.append(result)
                except Exception as e:
                    logger.info(
                        "Error! Encountered exception while opening file {file_path}, error: {e}".format(file_path, e)
                    )
        return results

    def generate_report_on_allure_server(self):
        """
        This method would generate the report on the remote allure server and display the report URL in the log
        """
        logger.info("Generating report on allure server")
        time.sleep(30)
        params = {"project_id": self.project_id}
        url = self.base_url + "/generate-report"
        response = requests.get(url, params=params, headers=self.http_headers)

        if not response.ok:
            logger.error("Failed to generate report on allure server, error: {}".format(response.content))
        else:
            resJson = response.json()
            if resJson["data"] and resJson["data"]["report_url"]:
                report_url = resJson["data"]["report_url"]
            else:
                logger.error(
                    "ERROR! Data was not found in response for generating allure report. res: {resJson}".format(resJson)
                )
                report_url = ""
            return report_url

    def clean_results_on_allure_server(self):
        """
        This method would clean results for project on the remote allure server
        """
        time.sleep(30)
        url = self.base_url + "/clean-results"
        params = {"project_id": self.project_id}
        response = requests.get(url, params=params, headers=self.http_headers)

        if not response.ok:
            logger.error("Failed to clean results on allure server, error: {}".format(response.content))

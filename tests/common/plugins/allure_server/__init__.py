import time
import logging
import os
import requests
import base64

logger = logging.getLogger()


def pytest_addoption(parser):
    """
    Parse pytest options
    :param parser: pytest buildin
    """
    parser.addoption('--allure_server_addr', action='store', default=None, help='Allure server address: IP/domain name')
    parser.addoption('--allure_server_port', action='store', default=5050, help='Allure server port')
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
                try:
                    allure_server_odb = AllureServer(allure_server_addr, allure_server_port, allure_report_dir,
                                                     allure_server_project_id)
                    allure_server_odb.generate_allure_report()
                except Exception as err:
                    logger.error('Failed to upload allure report to server. Allure report not available. '
                                 '\nError: {}'.format(err))
            else:
                logger.error('PyTest argument "--alluredir" not provided. Impossible to generate Allure report')


def get_time_stamp_str():
    """
    This method return string with current time
    :return: string, example: 16063138520755782
    """
    current_time = time.time()
    current_time_without_dot = str(current_time).replace('.', '')
    return current_time_without_dot


class AllureServer:
    def __init__(self, allure_server_ip, allure_server_port, allure_report_dir, project_id=None):
        self.allure_report_dir = allure_report_dir
        self.base_url = 'http://{}:{}/allure-docker-service'.format(allure_server_ip, allure_server_port)
        self.project_id = project_id if project_id else get_time_stamp_str()
        self.http_headers = {'Content-type': 'application/json'}

    def generate_allure_report(self):
        """
        This method creates new project(if need) on allure server, uploads test results to server and generates report
        """
        self.create_project_on_allure_server()
        self.upload_results_to_allure_server()
        self.generate_report_on_allure_server()

    def create_project_on_allure_server(self):
        """
        This method creates new project(if need) on allure server
        """
        data = {'id': self.project_id}
        url = self.base_url + '/projects'

        if requests.get(url + '/' + self.project_id).status_code != 200:
            logger.info('Creating project {} on allure server'.format(self.project_id))
            response = requests.post(url, json=data, headers=self.http_headers)
            if response.raise_for_status():
                logger.error('Failed to create project on allure server, error: {}'.format(response.content))
        else:
            logger.info('Allure project {} already exist on server. No need to create project'.format(self.project_id))

    def upload_results_to_allure_server(self):
        """
        This method uploads files from allure results folder to allure server
        """
        data = {'results': self.get_allure_files_content()}
        url = self.base_url + '/send-results?project_id=' + self.project_id

        logger.info('Sending allure results to allure server')
        response = requests.post(url, json=data, headers=self.http_headers)
        if response.raise_for_status():
            logger.error('Failed to upload results to allure server, error: {}'.format(response.content))

    def get_allure_files_content(self):
        """
        This method creates a list all files under allure report folder
        :return: list with allure folder content, example [{'file1': 'file content'}, {'file2': 'file2 content'}]
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
                            result['file_name'] = file
                            result['content_base64'] = b64_content.decode('UTF-8')
                            results.append(result)
                finally:
                    f.close()
        return results

    def generate_report_on_allure_server(self):
        """
        This method would generate the report on the remote allure server and display the report URL in the log
        """
        logger.info('Generating report on allure server')
        url = self.base_url + '/generate-report?project_id=' + self.project_id
        response = requests.get(url, headers=self.http_headers)

        if response.raise_for_status():
            logger.error('Failed to generate report on allure server, error: {}'.format(response.content))
        else:
            report_url = response.json()['data']['report_url']
            logger.info('Allure report URL: {}'.format(report_url))

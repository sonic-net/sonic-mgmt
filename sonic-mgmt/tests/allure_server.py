import time
import logging
import os
import requests
import base64
import re
import subprocess

logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger()

def get_time_stamp_str():
    """
    This method return string with current time
    :return: string, example: 16063138520755782
    """
    current_time = time.time()
    current_time_without_dot = str(current_time).replace(".", "")
    return current_time_without_dot


class AllureServer:
    def __init__(self, allure_server_host, allure_report_dir, allure_server_port=None, project_id=None):
        self.allure_report_dir = allure_report_dir
        if allure_server_port:
            self.base_url = "http://{}:{}/allure-docker-service".format(allure_server_host, allure_server_port)
        else:
            self.base_url = "http://{}/allure-docker-service".format(allure_server_host)
        self.project_id = str(project_id) if project_id else get_time_stamp_str()
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
        data = {"id": self.project_id}
        url = self.base_url + "/projects"

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


        #sometimes files sent is too much and allure needs more time to process before generating report
        #in this case, wait a bit and try again
        if response.status_code == 400 and "Try later" in response.json()["meta_data"]["message"]:
            logger.info("Got response to try again later. Sleeping for 5 minutes and checking if reports were generated...")
            get_reports_url = self.base_url + "/projects/" + self.project_id
            for i in range(5): #try 5 times
                logger.info("Attempt #{}".format(i))
                time.sleep(300)

                response = requests.get(get_reports_url, headers=self.http_headers)
                if not response.ok: 
                    continue

                resJson = response.json()
                logger.info("response for GET {}: {}".format(get_reports_url, resJson))
                reports = resJson["data"]["project"]["reports"]
                if len(reports) == 0:
                    continue

                for report_url in reports:
                    if "latest" in report_url:
                        return report_url
                
                #if code got here, somehow report links exist but 'latest' does not
                #strangee, but better to return some url than nothing, return 1st element
                return reports[0]

        if not response.ok:
            logger.error("Failed to generate report on allure server, error: {}".format(response.content))
            return ""

        resJson = response.json()
        if resJson["data"] and resJson["data"]["report_url"]:
            report_url = resJson["data"]["report_url"]
        else:
            logger.error(
                "ERROR! Data was not found in response for generating allure report. res: {}".format(resJson)
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

import requests
import logging
import yaml
import os

from CustomSkipIf import CustomSkipIf

logger = logging.getLogger()


class SkipIf(CustomSkipIf):
    def __init__(self, ignore_list, pytest_item_obj):
        super(SkipIf, self).__init__(ignore_list, pytest_item_obj)
        self.name = 'GitHub'
        self.credentials = self.get_cred()

    def get_cred(self):
        """
        Get GitHub API credentials
        :return: dictionary with GitHub credentials {'user': aaa, 'api_token': 'bbb'}
        """
        cred_file_name = 'credentials.yaml'
        cred_folder_path = os.path.dirname(__file__)
        cred_file_path = os.path.join(cred_folder_path, cred_file_name)

        with open(cred_file_path) as cred_file:
            cred = yaml.load(cred_file, Loader=yaml.FullLoader).get(self.name)

        return cred

    def is_skip_required(self, skip_dict_result):
        """
        Make decision about ignore - is it required or not
        :param skip_dict_result: shared dictionary with data about skip test
        :return: updated skip_dict_result
        """
        github_api = GitHubApi(self.credentials.get('user'), self.credentials.get('api_token'))

        for github_issue in self.ignore_list:
            if github_api.is_github_issue_active(github_issue):
                skip_dict_result[self.name] = github_issue
                break
        return skip_dict_result


class GitHubApi:
    """
    This class allows user to query github issues status
    Usage example:
    github = GitHubApi('user', 'api_token')
    github.is_github_issue_active(github_issue)
    """

    def __init__(self, github_username, api_token):
        self.auth = (github_username, api_token)

    @staticmethod
    def get_github_issue_api_url(issue_url):
        """
        Get correct github api URL based on browser URL from user
        :param issue_url: github issue url
        :return: github issue api url
        """
        return issue_url.replace('github.com', 'api.github.com/repos')

    def make_github_request(self, url):
        """
        Send API request to github
        :param url: github api url
        :return: dictionary with data
        """
        response = requests.get(url, auth=self.auth)
        response.raise_for_status()
        return response.json()

    def is_github_issue_active(self, issue_url):
        """
        Check that issue active or not
        :param issue_url:  github issue URL
        :return: True/False
        """
        issue_url = self.get_github_issue_api_url(issue_url)
        response = self.make_github_request(issue_url)
        if response.get('state') == 'closed':
            if self.is_duplicate(response):
                logger.warning('GitHub issue: {} looks like duplicate and was closed. Please re-check and ignore'
                               'the test on the parent issue'.format(issue_url))
            return False
        return True

    @staticmethod
    def is_duplicate(issue_data):
        """
        Check if issue duplicate or note
        :param issue_data: github response dict
        :return: True/False
        """
        for label in issue_data['labels']:
            if 'duplicate' in label['name'].lower():
                return True
        return False

"""For checking issue state based on supplied issue URL.
"""
import logging
import multiprocessing
import os
import re
import yaml

import requests

from abc import ABCMeta, abstractmethod

logger = logging.getLogger(__name__)

CREDENTIALS_FILE = 'credentials.yaml'


class IssueCheckerBase(object):
    """Base class for issue checker
    """
    __metaclass__ = ABCMeta

    def __init__(self, url):
        self.url = url

    @abstractmethod
    def is_active(self):
        """
        Check if the issue is still active
        """
        return True


class GitHubIssueChecker(IssueCheckerBase):
    """GitHub issue state checker
    """

    NAME = 'GitHub'

    def __init__(self, url):
        super(GitHubIssueChecker, self).__init__(url)
        self.user = ''
        self.api_token = ''
        self.api_url = url.replace('github.com', 'api.github.com/repos')
        self.get_cred()

    def get_cred(self):
        """Get GitHub API credentials
        """
        creds_folder_path = os.path.dirname(__file__)
        creds_file_path = os.path.join(creds_folder_path, CREDENTIALS_FILE)
        try:
            with open(creds_file_path) as creds_file:
                creds = yaml.safe_load(creds_file)
                if creds is not None:
                    github_creds = creds.get(self.NAME, {})
                    self.user = github_creds.get('user', '')
                    self.api_token = github_creds.get('api_token', '')
                else:
                    self.user = os.environ.get("GIT_USER_NAME")
                    self.api_token = os.environ.get("GIT_API_TOKEN")
        except Exception as e:
            logger.error('Load credentials from {} failed with error: {}'.format(creds_file_path, repr(e)))

    def is_active(self):
        """Check if the issue is still active.

        If unable to get issue state, always consider it as active.

        Returns:
            bool: False if the issue is closed else True.
        """
        try:
            response = requests.get(self.api_url, auth=(self.user, self.api_token))
            response.raise_for_status()
            issue_data = response.json()
            if issue_data.get('state', '') == 'closed':
                logger.debug('Issue {} is closed'.format(self.url))
                labels = issue_data.get('labels', [])
                if any(['name' in label and 'duplicate' in label['name'].lower() for label in labels]):
                    logger.warning('GitHub issue: {} looks like duplicate and was closed. Please re-check and ignore'
                        'the test on the parent issue'.format(self.url))
                return False
        except Exception as e:
            logger.error('Get details for {} failed with: {}'.format(self.url, repr(e)))

        logger.debug('Issue {} is active. Or getting issue state failed, consider it as active anyway'.format(self.url))
        return True


def issue_checker_factory(url):
    """Factory function for creating issue checker object based on the domain name in the issue URL.

    Args:
        url (str): Issue URL.

    Returns:
        obj: An instance of issue checker.
    """
    m = re.match('https?://([^/]+)', url)
    if m and len(m.groups()) > 0:
        domain_name = m.groups()[0].lower()
        if 'github' in domain_name:
            return GitHubIssueChecker(url)
        else:
            logger.error('Unknown issue website: {}'.format(domain_name))
    logger.error('Creating issue checker failed. Bad issue url {}'.format(url))
    return None


def check_issues(issues):
    """Check state of the specified issues.

    Because issue state checking may involve sending HTTP request. This function uses parallel run to speed up
    issue status checking.

    Args:
        issues (list of str): List of issue URLs.

    Returns:
        dict: Issue state check result. Key is issue URL, value is either True or False based on issue state.
    """
    checkers = [c for c in [issue_checker_factory(issue) for issue in issues] if c is not None]
    if not checkers:
        logger.error('No checker created for issues: {}'.format(issues))
        return {}

    check_results = multiprocessing.Manager().dict()
    check_procs = []

    def _check_issue(checker, results):
        results[checker.url] = checker.is_active()

    for checker in checkers:
        check_procs.append(multiprocessing.Process(target=_check_issue, args=(checker, check_results,)))

    for proc in check_procs:
        proc.start()
    for proc in check_procs:
        proc.join(timeout=60)

    return check_results

"""For checking issue state based on supplied issue URL.
"""
import logging
import os
import re
from abc import ABCMeta, abstractmethod
from urllib.parse import urlencode

import requests
import six

logger = logging.getLogger(__name__)


class IssueCheckerBase(six.with_metaclass(ABCMeta, object)):
    """Base class for issue checker
    """

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

    def __init__(self, url, proxies):
        super(GitHubIssueChecker, self).__init__(url)
        self.api_url = url.replace('github.com', 'api.github.com/repos')
        self.proxies = proxies

    def is_active(self):
        """Check if the GitHub issue is still active.

        Attempt to fetch issue details via proxy if configured. If proxy fails, retry with direct GitHub API URL.
        If unable to retrieve issue state, assume the issue is active (safe default).

        Returns:
            bool: False if the issue is closed else True.
        """

        def fetch_issue(url):
            response = requests.get(url, proxies=self.proxies, timeout=10)
            response.raise_for_status()
            return response.json()

        direct_url = self.api_url
        proxy_url = os.getenv("SONIC_AUTOMATION_PROXY_GITHUB_ISSUES_URL")

        issue_data = None

        # Attempt to access via proxy first (if configured)
        # The proxy is used to work around GitHub's unauthenticated rate limit (60 requests/hour per IP).
        # For details, refer to GitHub API rate limits documentation:
        # https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28#primary-rate-limit-for-unauthenticated-users
        if proxy_url:
            try:
                proxy_endpoint = f"{proxy_url.rstrip('/')}/?{urlencode({'github_issue_url': direct_url})}"
                logger.info("Attempting to access GitHub API via proxy.")
                issue_data = fetch_issue(proxy_endpoint)
            except Exception as proxy_err:
                logger.warning(f"Proxy access failed: {proxy_err}. Falling back to direct API.")

        # Fallback to direct URL if proxy is not set or fails
        if issue_data is None:
            try:
                logger.info(f"Accessing GitHub API directly: {direct_url}")
                issue_data = fetch_issue(direct_url)
            except Exception as direct_err:
                logger.error(f"Access GitHub API directly failed for {direct_url}: {direct_err}")
                logger.debug(f"Issue {direct_url} is considered active due to API access failure.")
                return True

        # Check issue state
        if issue_data.get('state') == 'closed':
            logger.debug(f"Issue {direct_url} is closed.")
            labels = issue_data.get('labels', [])
            if any('name' in label and 'duplicate' in label['name'].lower() for label in labels):
                logger.warning(
                    f"GitHub issue {direct_url} appears to be a duplicate and was closed. "
                    f"Consider ignoring related test failures.")
            return False

        logger.debug(f"Issue {direct_url} is active.")
        return True


def issue_checker_factory(url, proxies):
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
            return GitHubIssueChecker(url, proxies)
        else:
            logger.error('Unknown issue website: {}'.format(domain_name))
    logger.error('Creating issue checker failed. Bad issue url {}'.format(url))
    return None


def check_issue(issue, proxies=None):
    """Check state of the specified issue.

    Args:
        issue (str): Issue URL.

    Returns:
        dict: Issue state check result. Key is issue URL, value is either True or False based on issue state.
    """
    checker = issue_checker_factory(issue, proxies)
    if not checker:
        logger.error('No checker created for issue: {}'.format(issue))
        return {}

    return {issue: checker.is_active()}

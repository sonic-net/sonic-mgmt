"""For checking issue state based on supplied issue URL.
"""
import logging
import multiprocessing
import os
import re
from abc import ABCMeta, abstractmethod
from urllib.parse import urlencode

import requests
import six

logger = logging.getLogger(__name__)

# Circuit breaker for issue state checks. When the GitHub API is unreachable
# (e.g. runners without internet access or with a dead proxy), every single
# lookup burns a full HTTP timeout and logs an error before falling back to
# "issue is active". With hundreds of issue URLs in the mark conditions files
# that adds up to tens of minutes of pure waiting per session. After
# MAX_CONSECUTIVE_API_FAILURES lookups fail in a row without a single success,
# stop calling the API for the rest of the session and apply the same safe
# fallback (treat issues as active) immediately.
MAX_CONSECUTIVE_API_FAILURES = 3
_api_failure_streak = 0
_issue_check_disabled = False


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

        Returns:
            bool: False if the issue is closed else True.
        """
        return self.check()[0]

    def check(self):
        """Check if the GitHub issue is still active, reporting API reachability.

        Attempt to fetch issue details via proxy if configured. If proxy fails, retry with direct GitHub API URL.
        If unable to retrieve issue state, assume the issue is active (safe default).

        Returns:
            tuple of (bool, bool): First item is False if the issue is closed else True. Second item is False
                if the issue state could not be fetched from the API (the first item is then the safe default).
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
                return True, False

        # Check issue state
        if issue_data.get('state') == 'closed':
            logger.debug(f"Issue {direct_url} is closed.")
            labels = issue_data.get('labels', [])
            if any('name' in label and 'duplicate' in label['name'].lower() for label in labels):
                logger.warning(
                    f"GitHub issue {direct_url} appears to be a duplicate and was closed. "
                    f"Consider ignoring related test failures.")
            return False, True

        logger.debug(f"Issue {direct_url} is active.")
        return True, True


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


def check_issues(issues, proxies=None):
    """Check state of the specified issues.

    Because issue state checking may involve sending HTTP request. This function uses parallel run to speed up
    issue status checking.

    Args:
        issues (list of str): List of issue URLs.

    Returns:
        dict: Issue state check result. Key is issue URL, value is either True or False based on issue state.
    """
    global _api_failure_streak, _issue_check_disabled

    if _issue_check_disabled:
        logger.debug('Issue state check is disabled for this session, treating {} issue(s) as active'
                     .format(len(issues)))
        return {issue: True for issue in issues}

    checkers = [c for c in [issue_checker_factory(issue, proxies) for issue in issues] if c is not None]
    if not checkers:
        logger.error('No checker created for issues: {}'.format(issues))
        return {}

    manager = multiprocessing.Manager()
    check_results = manager.dict()
    api_failures = manager.dict()

    def _check_issue(checker, results, failures):
        checker_check = getattr(checker, 'check', None)
        if checker_check is not None:
            active, api_ok = checker_check()
        else:
            active, api_ok = checker.is_active(), True
        results[checker.url] = active
        if not api_ok:
            failures[checker.url] = True

    check_procs = []
    for checker in checkers:
        check_procs.append(multiprocessing.Process(target=_check_issue, args=(checker, check_results, api_failures,)))

    for proc in check_procs:
        proc.start()
    for proc in check_procs:
        proc.join(timeout=60)

    if api_failures:
        _api_failure_streak += len(api_failures)
        if _api_failure_streak >= MAX_CONSECUTIVE_API_FAILURES:
            _issue_check_disabled = True
            logger.warning(
                'Disabling issue state checks for the rest of this session after {} consecutive API failures '
                '(GitHub API unreachable from this host?). Remaining issue URLs will be treated as active.'
                .format(_api_failure_streak))
    else:
        _api_failure_streak = 0

    return dict(check_results)

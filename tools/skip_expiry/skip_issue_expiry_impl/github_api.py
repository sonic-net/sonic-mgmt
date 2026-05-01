import logging
from typing import Dict, List, Optional
from urllib.parse import quote

import requests

from .models import IssueRef

logger = logging.getLogger(__name__)


class GitHubApiClient:
    """Small GitHub REST API wrapper used by the skip-expiry workflow."""

    def __init__(self, token: str, api_base_url: str = "https://api.github.com") -> None:
        if not token:
            raise ValueError("GITHUB_TOKEN is required")

        self.api_base_url = api_base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "sonic-mgmt-skip-expiry-workflow",
            }
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, object]] = None,
        json_body: Optional[Dict[str, object]] = None,
        accept: Optional[str] = None,
    ) -> requests.Response:
        url = f"{self.api_base_url}{path}"
        headers = None
        if accept:
            headers = {"Accept": accept}

        response = self.session.request(method, url, params=params, json=json_body, headers=headers, timeout=30)
        if response.status_code >= 400:
            logger.error("GitHub API %s %s failed with %d: %s", method, path, response.status_code, response.text)
            response.raise_for_status()
        return response

    def _paginate(
        self,
        path: str,
        *,
        per_page: int = 100,
        accept: Optional[str] = None,
        params: Optional[Dict[str, object]] = None,
    ) -> List[Dict[str, object]]:
        page = 1
        items: List[Dict[str, object]] = []
        while True:
            merged_params = {"per_page": per_page, "page": page}
            if params:
                merged_params.update(params)

            response = self._request("GET", path, params=merged_params, accept=accept)
            page_items = response.json()
            if not page_items:
                break
            items.extend(page_items)
            if len(page_items) < per_page:
                break
            page += 1
        return items

    def get_issue(self, issue: IssueRef) -> Dict[str, object]:
        return self._request("GET", issue.api_path).json()

    def get_issue_timeline(self, issue: IssueRef) -> List[Dict[str, object]]:
        timeline_path = f"{issue.api_path}/timeline"
        return self._paginate(
            timeline_path,
            accept="application/vnd.github.mockingbird-preview+json",
        )

    def get_issue_comments(self, issue: IssueRef) -> List[Dict[str, object]]:
        comments_path = f"{issue.api_path}/comments"
        return self._paginate(comments_path)

    def add_label(self, issue: IssueRef, label: str) -> None:
        logger.info("Adding label %s to %s", label, issue.html_url)
        self._request("POST", f"{issue.api_path}/labels", json_body={"labels": [label]})

    def remove_label(self, issue: IssueRef, label: str) -> None:
        logger.info("Removing label %s from %s", label, issue.html_url)
        encoded_label = quote(label, safe="")
        response = self.session.delete(
            f"{self.api_base_url}{issue.api_path}/labels/{encoded_label}",
            timeout=30,
        )
        if response.status_code in (200, 204, 404):
            return
        if response.status_code >= 400:
            logger.error(
                "Failed to remove label %s from %s: %d %s",
                label, issue.html_url,
                response.status_code, response.text)
            response.raise_for_status()

    def create_comment(self, issue: IssueRef, body: str) -> None:
        logger.info("Creating comment on %s", issue.html_url)
        self._request("POST", f"{issue.api_path}/comments", json_body={"body": body})

import logging
import time
from typing import Dict, List, Optional
from urllib.parse import quote

import requests

from .models import IssueRef

logger = logging.getLogger(__name__)


class GitHubApiClient:
    """Small GitHub REST API wrapper used by the skip-expiry workflow."""

    def __init__(
        self,
        token: str,
        api_base_url: str = "https://api.github.com",
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        max_backoff_seconds: float = 60.0,
    ) -> None:
        if not token:
            raise ValueError("GITHUB_TOKEN is required")

        self.api_base_url = api_base_url.rstrip("/")
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.max_backoff_seconds = max_backoff_seconds
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "sonic-mgmt-skip-expiry-workflow",
            }
        )

    def _parse_retry_after(self, retry_after_header: str, default_backoff: float) -> float:
        """Parse Retry-After header, tolerating both seconds (int) and HTTP-date formats."""
        try:
            return float(retry_after_header)
        except ValueError:
            logger.warning(
                "Retry-After header not numeric (%r, likely HTTP-date); using default backoff %.1fs",
                retry_after_header, default_backoff,
            )
            return default_backoff

    def _cap_backoff(self, backoff_secs: float) -> float:
        """Cap backoff to prevent unbounded exponential growth."""
        return min(backoff_secs, self.max_backoff_seconds)

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, object]] = None,
        json_body: Optional[Dict[str, object]] = None,
        accept: Optional[str] = None,
        success_statuses: Optional[List[int]] = None,
    ) -> requests.Response:
        url = f"{self.api_base_url}{path}"
        headers = None
        if accept:
            headers = {"Accept": accept}

        last_exc: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.request(
                    method, url, params=params, json=json_body, headers=headers, timeout=30
                )
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    sleep_secs = self.backoff_factor * (2 ** attempt)
                    logger.warning(
                        "GitHub API %s %s raised %s (attempt %d/%d), retrying in %.1fs",
                        method, path, exc, attempt + 1, self.max_retries + 1, sleep_secs,
                    )
                    time.sleep(sleep_secs)
                continue

            last_exc = None

            if success_statuses and response.status_code in success_statuses:
                return response

            if response.status_code == 429:
                default_backoff = self._cap_backoff(self.backoff_factor * (2 ** attempt))
                retry_after = self._parse_retry_after(
                    response.headers.get("Retry-After", ""), default_backoff
                )
                if attempt < self.max_retries:
                    logger.warning(
                        "GitHub API %s %s rate limited (429), retrying after %.1fs",
                        method, path, retry_after,
                    )
                    time.sleep(retry_after)
                    continue
                logger.error("GitHub API %s %s failed with 429 after %d retries", method, path, self.max_retries)
                response.raise_for_status()
                return response

            # Check for 403 Forbidden with rate-limit exhaustion
            if response.status_code == 403:
                remaining = response.headers.get("X-RateLimit-Remaining")
                if remaining == "0" and attempt < self.max_retries:
                    reset_time = response.headers.get("X-RateLimit-Reset")
                    sleep_secs = float(reset_time) - time.time() if reset_time else self._cap_backoff(
                        self.backoff_factor * (2 ** attempt)
                    )
                    logger.warning(
                        "GitHub API %s %s rate limited (403, limit exhausted), retrying after %.1fs",
                        method, path, sleep_secs,
                    )
                    time.sleep(sleep_secs)
                    continue

            if response.status_code >= 500 and attempt < self.max_retries:
                sleep_secs = self._cap_backoff(self.backoff_factor * (2 ** attempt))
                logger.warning(
                    "GitHub API %s %s failed with %d (attempt %d/%d), retrying in %.1fs",
                    method, path, response.status_code, attempt + 1, self.max_retries + 1, sleep_secs,
                )
                time.sleep(sleep_secs)
                continue

            if response.status_code >= 400:
                logger.error(
                    "GitHub API %s %s failed with %d: %s", method, path, response.status_code, response.text
                )
                response.raise_for_status()

            return response

        if last_exc is not None:
            raise last_exc
        raise RuntimeError(f"GitHub API {method} {path} failed after {self.max_retries} retries")

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
        self._request(
            "DELETE",
            f"{issue.api_path}/labels/{encoded_label}",
            success_statuses=[404],
        )

    def create_comment(self, issue: IssueRef, body: str) -> None:
        logger.info("Creating comment on %s", issue.html_url)
        self._request("POST", f"{issue.api_path}/comments", json_body={"body": body})

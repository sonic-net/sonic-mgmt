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
        max_backoff_seconds: float = 30.0,
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

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, object]] = None,
        json_body: Optional[Dict[str, object]] = None,
        accept: Optional[str] = None,
        success_statuses: Optional[set] = None,
    ) -> requests.Response:
        url = f"{self.api_base_url}{path}"
        headers = None
        if accept:
            headers = {"Accept": accept}

        allowed_statuses = success_statuses or set()

        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.request(method, url, params=params, json=json_body, headers=headers, timeout=30)
            except requests.RequestException as exc:
                if attempt >= self.max_retries:
                    logger.error("GitHub API %s %s failed after retries: %s", method, path, exc)
                    raise

                delay = self._compute_backoff_seconds(attempt)
                logger.warning(
                    "GitHub API %s %s request exception (%s); retrying in %.1fs (attempt %d/%d)",
                    method,
                    path,
                    type(exc).__name__,
                    delay,
                    attempt + 1,
                    self.max_retries,
                )
                time.sleep(delay)
                continue

            if response.status_code < 400 or response.status_code in allowed_statuses:
                return response

            if self._should_retry_response(response) and attempt < self.max_retries:
                delay = self._resolve_retry_delay(response, attempt)
                logger.warning(
                    "GitHub API %s %s returned %d; retrying in %.1fs (attempt %d/%d)",
                    method,
                    path,
                    response.status_code,
                    delay,
                    attempt + 1,
                    self.max_retries,
                )
                time.sleep(delay)
                continue

            logger.error("GitHub API %s %s failed with %d: %s", method, path, response.status_code, response.text)
            response.raise_for_status()

        raise RuntimeError("Unexpected retry loop termination")

    def _resolve_retry_delay(self, response: requests.Response, attempt: int) -> float:
        retry_after = self._parse_retry_after_seconds(response)
        if retry_after is not None:
            return retry_after
        return self._compute_backoff_seconds(attempt)

    def _compute_backoff_seconds(self, attempt: int) -> float:
        delay = self.backoff_factor * (2**attempt)
        return min(delay, self.max_backoff_seconds)

    @staticmethod
    def _parse_retry_after_seconds(response: requests.Response) -> Optional[float]:
        retry_after = response.headers.get("Retry-After")
        if not retry_after:
            return None
        try:
            parsed = float(retry_after)
        except ValueError:
            return None

        return max(parsed, 0.0)

    @staticmethod
    def _should_retry_response(response: requests.Response) -> bool:
        status_code = response.status_code
        if status_code == 429 or status_code >= 500:
            return True

        if status_code == 403:
            rate_remaining = (response.headers.get("X-RateLimit-Remaining") or "").strip()
            if rate_remaining == "0" or response.headers.get("Retry-After"):
                return True

        return False

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
            success_statuses={404},
        )

    def create_comment(self, issue: IssueRef, body: str) -> None:
        logger.info("Creating comment on %s", issue.html_url)
        self._request("POST", f"{issue.api_path}/comments", json_body={"body": body})

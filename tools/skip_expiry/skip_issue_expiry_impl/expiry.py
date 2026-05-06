import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from .config import SkipExpiryConfig
from .github_api import GitHubApiClient
from .models import IssueRef

logger = logging.getLogger(__name__)

EXPIRED_LABEL = "skip-wf-issue-expired"
EXPIRED_MARKER = "<!-- skip-expiry:state=expired -->"
ACTIVE_MARKER = "<!-- skip-expiry:state=active -->"


@dataclass
class ManagedState:
    value: Optional[str] = None
    at: Optional[datetime] = None


class SkipExpiryManager:
    """Handles issue expiry transition logic for skip/xfail tracked issues."""

    def __init__(
        self,
        api_client: GitHubApiClient,
        config: SkipExpiryConfig,
        bot_login: str,
        no_op: bool = False,
    ) -> None:
        self.api_client = api_client
        self.config = config
        self.bot_login = bot_login
        self.no_op = no_op

    def process_issue(self, issue_ref: IssueRef) -> None:
        issue = self.api_client.get_issue(issue_ref)

        if issue.get("state") != "open":
            if self.no_op:
                created_at = self._parse_github_timestamp(issue.get("created_at"))
                created_text = created_at.isoformat() if created_at else "unknown"
                logger.info(
                    "NO-OP issue %s created=%s expired_now=n/a action=skip_closed",
                    issue_ref.html_url,
                    created_text,
                )
                return

            logger.info("Skipping closed issue %s", issue_ref.html_url)
            return

        timeline = self.api_client.get_issue_timeline(issue_ref)
        created_at = self._resolve_created_at(timeline, issue.get("created_at"))
        if not created_at:
            logger.error("Unable to determine created_at for %s; skipping", issue_ref.html_url)
            return

        expired_now = self._is_expired(created_at)
        managed_state = self._resolve_managed_state(timeline, self.api_client.get_issue_comments(issue_ref))
        labels = {label.get("name") for label in issue.get("labels", []) if isinstance(label, dict)}
        action = self._determine_action(expired_now, labels, managed_state)

        if self.no_op:
            logger.info(
                "NO-OP issue %s created=%s expired_now=%s action=%s",
                issue_ref.html_url,
                created_at.isoformat(),
                expired_now,
                action,
            )
            return

        logger.info(
            "Issue %s created %s, expired_now=%s, managed_state=%s, action=%s",
            issue_ref.html_url,
            created_at.isoformat(),
            expired_now,
            managed_state.value,
            action,
        )

        if expired_now:
            self._handle_expired_transition(issue_ref, labels, managed_state)
            return

        self._handle_active_transition(issue_ref, labels, managed_state)

    def _handle_expired_transition(self, issue_ref: IssueRef, labels: set, managed_state: ManagedState) -> None:
        if managed_state.value == "expired":
            logger.info("Issue %s already managed as expired; no action", issue_ref.html_url)
            return

        if EXPIRED_LABEL not in labels:
            self.api_client.add_label(issue_ref, EXPIRED_LABEL)

        self.api_client.create_comment(issue_ref, self._build_expired_comment())
        logger.info("Issue %s marked as expired", issue_ref.html_url)

    def _handle_active_transition(self, issue_ref: IssueRef, labels: set, managed_state: ManagedState) -> None:
        if managed_state.value != "expired":
            logger.info("Issue %s is active and was never managed as expired; no action", issue_ref.html_url)
            return

        if EXPIRED_LABEL in labels:
            self.api_client.remove_label(issue_ref, EXPIRED_LABEL)

        self.api_client.create_comment(issue_ref, self._build_active_comment())
        logger.info("Issue %s transitioned back to active from expired", issue_ref.html_url)

    def _is_expired(self, created_at: datetime) -> bool:
        cutoff = created_at + timedelta(days=self.config.expiry_days)
        return datetime.now(timezone.utc) >= cutoff

    def _resolve_created_at(
        self,
        timeline: List[Dict[str, object]],
        fallback_created_at: Optional[str],
    ) -> Optional[datetime]:
        created_candidates: List[datetime] = []

        for event in timeline:
            if event.get("event") == "created":
                parsed = self._parse_github_timestamp(event.get("created_at"))
                if parsed:
                    created_candidates.append(parsed)

        if created_candidates:
            return min(created_candidates)

        return self._parse_github_timestamp(fallback_created_at)

    def _resolve_managed_state(
        self,
        timeline: List[Dict[str, object]],
        comments: List[Dict[str, object]],
    ) -> ManagedState:
        state = ManagedState()

        def apply(value: str, event_ts: Optional[datetime]) -> None:
            if event_ts is None:
                return
            if state.at is None or event_ts >= state.at:
                state.value = value
                state.at = event_ts

        for event in timeline:
            if event.get("event") not in {"labeled", "unlabeled"}:
                continue
            actor = (event.get("actor") or {}).get("login")
            label_name = ((event.get("label") or {}).get("name") or "").strip()
            if actor != self.bot_login or label_name != EXPIRED_LABEL:
                continue

            event_ts = self._parse_github_timestamp(event.get("created_at"))
            if event.get("event") == "labeled":
                apply("expired", event_ts)
            else:
                apply("active", event_ts)

        for comment in comments:
            actor = (comment.get("user") or {}).get("login")
            if actor != self.bot_login:
                continue

            body = str(comment.get("body") or "")
            event_ts = self._parse_github_timestamp(comment.get("created_at"))
            if EXPIRED_MARKER in body:
                apply("expired", event_ts)
            elif ACTIVE_MARKER in body:
                apply("active", event_ts)

        return state

    def _build_expired_comment(self) -> str:
        mentions = " ".join(f"@{name}" for name in self.config.maintainers)
        return (
            f"{EXPIRED_MARKER}\n"
            f"Skip-expiry workflow notice: this issue has crossed the configured expiry window "
            f"({self.config.expiry_days} days from creation).\n"
            f"Maintainers: {mentions}\n"
            "Please triage and either resolve/remove the conditional mark reference or adjust policy as needed."
        )

    def _build_active_comment(self) -> str:
        mentions = " ".join(f"@{name}" for name in self.config.maintainers)
        return (
            f"{ACTIVE_MARKER}\n"
            "Skip-expiry workflow update: this issue is no longer considered expired under the current policy.\n"
            f"Maintainers: {mentions}\n"
            "The workflow removed its expired status for this issue."
        )

    @staticmethod
    def _determine_action(expired_now: bool, labels: set, managed_state: ManagedState) -> str:
        if expired_now:
            if managed_state.value == "expired":
                return "no_action_already_expired"

            planned = []
            if EXPIRED_LABEL not in labels:
                planned.append(f"add_label:{EXPIRED_LABEL}")
            planned.append("create_comment:expired")
            return ",".join(planned)

        if managed_state.value != "expired":
            return "no_action_already_active"

        planned = []
        if EXPIRED_LABEL in labels:
            planned.append(f"remove_label:{EXPIRED_LABEL}")
        planned.append("create_comment:active")
        return ",".join(planned)

    @staticmethod
    def _parse_github_timestamp(raw_ts: object) -> Optional[datetime]:
        if not isinstance(raw_ts, str) or not raw_ts:
            return None
        try:
            return datetime.fromisoformat(raw_ts.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            logger.warning("Unable to parse GitHub timestamp: %s", raw_ts)
            return None

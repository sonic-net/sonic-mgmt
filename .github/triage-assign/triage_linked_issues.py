"""Mark issues as triaged once a pull request is linked to fix them.

An issue counts as linked when GitHub lists it in the pull request's
`closingIssuesReferences`: the PR description says "Fixes #123" / "Closes #123"
(or another closing keyword), or the issue was linked from the PR's
Development sidebar. These are the issues GitHub shows as linked on the issue
page, and closes when the PR merges.

For every such issue that is open, in this repository and not yet labelled
TRIAGED_LABEL (default "Triaged"), the script:
  * adds TRIAGED_LABEL and AUTO_TRIAGED_LABEL (default "auto-triaged"), and
  * assigns the issue to the pull request author or, when GitHub will not let
    them be assigned (only sonic-net members, repository collaborators and
    people who have commented on the issue can be), posts a comment on the
    issue mentioning them instead.

AUTO_TRIAGED_LABEL records that the triage was automatic. Triagers can tell it
apart from a human triage with `label:Triaged -label:auto-triaged`, and
removing it confirms the triage: the script never touches the issue again.

When a pull request is closed without being merged, each issue it linked that
still carries AUTO_TRIAGED_LABEL, and that no other open pull request links,
loses both labels, and the PR author is unassigned if this script assigned
them.

GitHub fires no workflow event when an issue is linked from the sidebar, so
the workflow also runs a weekly scan of open, untriaged issues that have a
linked pull request.

Modes:
  PR_NUMBER set   -> handle that single pull request: triage its linked issues
                     when it is open, undo the automatic triage when it was
                     closed without merging, nothing when it was merged
  PR_NUMBER unset -> scan open issues with a linked pull request and no
                     TRIAGED_LABEL
"""

import logging
import os

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
GITHUB_REPOSITORY = os.environ["GITHUB_REPOSITORY"]
PR_NUMBER = os.environ.get("PR_NUMBER", "").strip()

TRIAGED_LABEL = os.environ.get("TRIAGED_LABEL", "").strip() or "Triaged"
AUTO_TRIAGED_LABEL = os.environ.get("AUTO_TRIAGED_LABEL", "").strip() or "auto-triaged"
AUTO_TRIAGED_COLOR = "ededed"
# The account GITHUB_TOKEN acts as; REST reports it as "github-actions[bot]",
# GraphQL as "github-actions".
BOT_LOGIN = os.environ.get("BOT_LOGIN", "").strip() or "github-actions"
DRY_RUN = os.environ.get("DRY_RUN", "false").strip().lower() in ("true", "t", "1", "yes", "y", "on")
SCAN_LIMIT = int(os.environ.get("SCAN_LIMIT", "0"))

API_URL = os.environ.get("GITHUB_API_URL", "https://api.github.com")
HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
COMMENT_MARKER = "<!-- triage-linked-issues:author={login} pr={pr_number} -->"

logger = logging.getLogger("triage_linked_issues")

ISSUE_FIELDS = """
    number
    state
    repository { nameWithOwner }
    labels(first: 50) { nodes { name } }
    assignees(first: 10) { nodes { login } }
"""

PULL_REQUEST_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      number
      state
      author { login __typename }
      closingIssuesReferences(first: 25) {
        nodes {
          %s
          closedByPullRequestsReferences(first: 10, includeClosedPrs: false) {
            nodes { number repository { nameWithOwner } }
          }
        }
      }
    }
  }
}
""" % ISSUE_FIELDS

# Searching from the issue side keeps the scan's cost proportional to the
# issues that still need triage, rather than to the open-PR backlog.
SCAN_QUERY = """
query($search: String!, $after: String) {
  search(type: ISSUE, query: $search, first: 50, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ... on Issue {
        %s
        closedByPullRequestsReferences(first: 10, includeClosedPrs: false) {
          nodes { number state repository { nameWithOwner } author { login __typename } }
        }
      }
    }
  }
}
""" % ISSUE_FIELDS

ASSIGNMENT_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    issue(number: $number) {
      timelineItems(last: 100, itemTypes: [ASSIGNED_EVENT]) {
        nodes { ... on AssignedEvent { actor { login } assignee { ... on User { login } } } }
      }
    }
  }
}
"""


def make_session(retry: Retry) -> requests.Session:
    session = requests.Session()
    session.headers.update(HEADERS)
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


# Every write except the comment is idempotent (adding a label or assignee that
# is already there, or removing one that is gone), so it is safe to retry on
# rate limiting and server errors.
SESSION = make_session(Retry(
    total=3, backoff_factor=2, status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=None, respect_retry_after_header=True, raise_on_status=False,
))
# A comment POST that failed with a server error may still have been created,
# so it is retried only when GitHub rejected it outright (rate limiting) or the
# connection never got through.
COMMENT_SESSION = make_session(Retry(
    total=3, connect=3, read=0, backoff_factor=2, status_forcelist=(429,),
    allowed_methods=None, respect_retry_after_header=True, raise_on_status=False,
))


def is_bot(login: str) -> bool:
    return login.lower().removesuffix("[bot]") == BOT_LOGIN.lower().removesuffix("[bot]")


def graphql(query: str, variables: dict) -> dict:
    response = SESSION.post(f"{API_URL}/graphql", json={"query": query, "variables": variables}, timeout=60)
    response.raise_for_status()
    payload = response.json()
    if payload.get("errors"):
        raise SystemExit(f"GraphQL query failed: {payload['errors']}")
    return payload["data"]


def rest(method: str, path: str, session: requests.Session = SESSION, **kwargs) -> requests.Response:
    response = session.request(method, f"{API_URL}{path}", timeout=30, **kwargs)
    response.raise_for_status()
    return response


def issue_path(issue_number: int) -> str:
    return f"/repos/{GITHUB_REPOSITORY}/issues/{issue_number}"


def label_names(issue: dict) -> set:
    return {label["name"] for label in issue["labels"]["nodes"]}


def in_this_repo(node: dict) -> bool:
    return node["repository"]["nameWithOwner"].lower() == GITHUB_REPOSITORY.lower()


def ensure_auto_triaged_label() -> None:
    response = SESSION.get(f"{API_URL}/repos/{GITHUB_REPOSITORY}/labels/{AUTO_TRIAGED_LABEL}", timeout=30)
    if response.status_code != 404:
        response.raise_for_status()
        return
    logger.info("Creating missing label '%s'.", AUTO_TRIAGED_LABEL)
    if DRY_RUN:
        return
    response = SESSION.post(
        f"{API_URL}/repos/{GITHUB_REPOSITORY}/labels",
        json={"name": AUTO_TRIAGED_LABEL, "color": AUTO_TRIAGED_COLOR,
              "description": "Triaged automatically because a pull request is linked to fix it"},
        timeout=30,
    )
    # 422 is "already_exists": another run created it in the meantime.
    if response.status_code != 422:
        response.raise_for_status()


def can_be_assigned(issue_number: int, login: str) -> bool:
    """Whether GitHub allows `login` to be assigned to this issue.

    Assigning someone GitHub does not allow does not fail: it drops them and
    still returns 201, hence the explicit check.
    """
    response = SESSION.get(f"{API_URL}{issue_path(issue_number)}/assignees/{login}", timeout=30)
    if response.status_code == 404:
        return False
    response.raise_for_status()
    return True


def already_commented(issue_number: int, login: str) -> bool:
    """Whether this script already posted its comment about `login` on the issue."""
    marker_prefix = COMMENT_MARKER.split(" pr=", 1)[0].format(login=login)
    url = f"{API_URL}{issue_path(issue_number)}/comments?per_page=100"
    while url:
        response = SESSION.get(url, timeout=30)
        response.raise_for_status()
        for comment in response.json():
            if is_bot((comment.get("user") or {}).get("login", "")) and marker_prefix in (comment.get("body") or ""):
                return True
        url = response.links.get("next", {}).get("url")
    return False


def unassignable_comment(pr_number: int, login: str) -> str:
    return (
        f"{COMMENT_MARKER.format(login=login, pr_number=pr_number)}\n"
        f"@{login} is working on this issue in #{pr_number}.\n\n"
        "GitHub does not allow this issue to be assigned to them automatically: assignees must be "
        "members of the sonic-net organization, collaborators on this repository, or have commented "
        f"on the issue. @{login}, leaving a comment here lets a maintainer assign it to you."
    )


def triage_issue(issue: dict, pr_number: int, author: dict) -> bool:
    """Label `issue` and assign (or mention) the PR author. Returns True when it changed."""
    issue_number = issue["number"]
    if not in_this_repo(issue):
        # A PR may close issues in other repositories, which this token cannot modify.
        logger.info("PR #%s: %s#%s is in another repository, skipping.",
                    pr_number, issue["repository"]["nameWithOwner"], issue_number)
        return False
    if issue["state"] != "OPEN" or TRIAGED_LABEL in label_names(issue):
        return False

    login = author.get("login", "")
    # Bot-authored PRs (dependabot, ...) label what they fix but assign no one.
    is_user = bool(login) and author.get("__typename") == "User"
    assignees = {assignee["login"].lower() for assignee in issue["assignees"]["nodes"]}
    assign = is_user and login.lower() not in assignees and can_be_assigned(issue_number, login)
    comment = is_user and login.lower() not in assignees and not assign
    if comment and already_commented(issue_number, login):
        comment = False

    actions = [f"label '{TRIAGED_LABEL}', '{AUTO_TRIAGED_LABEL}'"]
    if assign:
        actions.append(f"assign @{login}")
    if comment:
        actions.append(f"comment for @{login} (cannot be assigned)")
    logger.info("PR #%s links issue #%s: %s.", pr_number, issue_number, ", ".join(actions))
    if DRY_RUN:
        return True

    path = issue_path(issue_number)
    if assign:
        result = rest("POST", f"{path}/assignees", json={"assignees": [login]}).json()
        # Checked above, but GitHub drops an unassignable user silently
        # rather than failing, so fall back to the comment if it did.
        if login.lower() not in {assignee["login"].lower() for assignee in result.get("assignees", [])}:
            logger.warning("GitHub did not assign issue #%s to @%s.", issue_number, login)
            comment = not already_commented(issue_number, login)
    if comment:
        rest("POST", f"{path}/comments", session=COMMENT_SESSION, json={"body": unassignable_comment(pr_number, login)})
    # Labelled last: the label is what marks the issue as handled, so a
    # failure above leaves it to be retried by the next run.
    rest("POST", f"{path}/labels", json={"labels": [TRIAGED_LABEL, AUTO_TRIAGED_LABEL]})
    return True


def assigned_by_bot(issue_number: int, login: str) -> bool:
    """Whether the most recent assignment of `login` to the issue was made by this script."""
    owner, name = GITHUB_REPOSITORY.split("/", 1)
    data = graphql(ASSIGNMENT_QUERY, {"owner": owner, "name": name, "number": issue_number})
    events = [
        event for event in data["repository"]["issue"]["timelineItems"]["nodes"]
        if ((event.get("assignee") or {}).get("login") or "").lower() == login.lower()
    ]
    return bool(events) and is_bot((events[-1].get("actor") or {}).get("login") or "")


def untriage_issue(issue: dict, pr_number: int, login: str) -> bool:
    """Undo the automatic triage of `issue` for a PR closed unmerged. Returns True when it changed."""
    issue_number = issue["number"]
    if not in_this_repo(issue) or issue["state"] != "OPEN":
        return False
    # Without AUTO_TRIAGED_LABEL the triage was a human's, or a human confirmed it.
    if AUTO_TRIAGED_LABEL not in label_names(issue):
        return False
    other_prs = [
        pull_request["number"] for pull_request in issue["closedByPullRequestsReferences"]["nodes"]
        if in_this_repo(pull_request) and pull_request["number"] != pr_number
    ]
    if other_prs:
        logger.info("PR #%s closed unmerged, but issue #%s is still linked from #%s; leaving it triaged.",
                    pr_number, issue_number, ", #".join(map(str, other_prs)))
        return False

    assignees = {assignee["login"].lower() for assignee in issue["assignees"]["nodes"]}
    unassign = bool(login) and login.lower() in assignees and assigned_by_bot(issue_number, login)

    actions = [f"remove '{TRIAGED_LABEL}', '{AUTO_TRIAGED_LABEL}'"]
    if unassign:
        actions.append(f"unassign @{login}")
    logger.info("PR #%s closed unmerged, issue #%s: %s.", pr_number, issue_number, ", ".join(actions))
    if DRY_RUN:
        return True

    path = issue_path(issue_number)
    if unassign:
        rest("DELETE", f"{path}/assignees", json={"assignees": [login]})
    for label in (TRIAGED_LABEL, AUTO_TRIAGED_LABEL):
        response = SESSION.delete(f"{API_URL}{path}/labels/{label}", timeout=30)
        if response.status_code != 404:
            response.raise_for_status()
    return True


def handle_issue(handler, issue: dict, *args) -> tuple:
    """Run `handler` on one issue, isolating failures. Returns (changed, failed)."""
    try:
        return int(handler(issue, *args)), 0
    except requests.RequestException as exc:
        logger.error("Issue #%s: %s", issue["number"], exc)
        return 0, 1


def handle_pull_request(pr_number: int) -> int:
    owner, name = GITHUB_REPOSITORY.split("/", 1)
    data = graphql(PULL_REQUEST_QUERY, {"owner": owner, "name": name, "number": pr_number})
    pull_request = data["repository"]["pullRequest"]
    if not pull_request:
        raise SystemExit(f"PR #{pr_number} not found in {GITHUB_REPOSITORY}")

    author = pull_request.get("author") or {}
    issues = pull_request["closingIssuesReferences"]["nodes"]
    changed = failed = 0
    if pull_request["state"] == "OPEN":
        if issues:
            ensure_auto_triaged_label()
        for issue in issues:
            result = handle_issue(triage_issue, issue, pr_number, author)
            changed, failed = changed + result[0], failed + result[1]
    elif pull_request["state"] == "CLOSED":
        for issue in issues:
            result = handle_issue(untriage_issue, issue, pr_number, author.get("login", ""))
            changed, failed = changed + result[0], failed + result[1]
    else:
        logger.info("PR #%s is merged; nothing to do.", pr_number)
    logger.info("PR #%s (%s): changed %d linked issues.", pr_number, pull_request["state"].lower(), changed)
    return failed


def scan() -> int:
    search = f"repo:{GITHUB_REPOSITORY} is:issue is:open linked:pr -label:{TRIAGED_LABEL}"
    logger.info("Scanning: %s", search)
    ensure_auto_triaged_label()
    scanned = changed = failed = 0
    after = None
    while True:
        page = graphql(SCAN_QUERY, {"search": search, "after": after})["search"]
        for issue in page["nodes"]:
            if SCAN_LIMIT and scanned >= SCAN_LIMIT:
                logger.info("Reached SCAN_LIMIT of %d issues, stopping.", SCAN_LIMIT)
                logger.info("Scanned %d issues, triaged %d, %d failed.", scanned, changed, failed)
                return failed
            scanned += 1
            # The earliest open PR in this repository that links the issue.
            pull_requests = sorted(
                (pull_request for pull_request in issue["closedByPullRequestsReferences"]["nodes"]
                 if in_this_repo(pull_request) and pull_request["state"] == "OPEN"),
                key=lambda pull_request: pull_request["number"],
            )
            if not pull_requests:
                continue
            pull_request = pull_requests[0]
            result = handle_issue(triage_issue, issue, pull_request["number"], pull_request.get("author") or {})
            changed, failed = changed + result[0], failed + result[1]
        if not page["pageInfo"]["hasNextPage"]:
            break
        after = page["pageInfo"]["endCursor"]

    logger.info("Scanned %d issues, triaged %d, %d failed.", scanned, changed, failed)
    return failed


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if DRY_RUN:
        logger.info("DRY_RUN: logging the changes without applying them.")
    failed = handle_pull_request(int(PR_NUMBER)) if PR_NUMBER else scan()
    if failed:
        raise SystemExit(f"{failed} issue(s) could not be updated; see the errors above.")


if __name__ == "__main__":
    main()

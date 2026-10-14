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
apart from a human triage with `label:Triaged -label:auto-triaged`. Removing
AUTO_TRIAGED_LABEL confirms the triage: the script never touches the issue
again. Removing TRIAGED_LABEL rejects it: once anyone other than this script
has removed TRIAGED_LABEL from an issue, the script never triages it again.

An automatic triage is undone when no open pull request links the issue any
more: the PR was closed without merging, or the link was removed from its
description or sidebar. The issue loses both labels, and every assignee this
script assigned is unassigned. When another open PR still links the issue, the
labels stay and the assignment passes to that PR's author.

GitHub fires no workflow event when an issue is linked or unlinked from the
sidebar, or when a closing keyword is removed, so the workflow also runs a
scheduled scan. It first reconciles every open issue labelled
AUTO_TRIAGED_LABEL with its current links, then triages the open, untriaged
issues that have a linked pull request.

Modes:
  PR_NUMBER set   -> handle that single pull request: triage its linked issues
                     when it is open, reconcile them when it was closed
                     without merging, nothing when it was merged
  PR_NUMBER unset -> scan: reconcile AUTO_TRIAGED_LABEL issues, then triage
                     open issues with a linked pull request and no
                     TRIAGED_LABEL
"""

import logging
import os
import time

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
REST_TIMEOUT = 30
GRAPHQL_TIMEOUT = 60
# Rate-limited responses (403 or 429) are retried this many times, waiting as
# long as GitHub asks, but giving up when it asks for more than
# RATE_LIMIT_MAX_WAIT seconds.
RATE_LIMIT_RETRIES = 3
RATE_LIMIT_MAX_WAIT = 300
# GitHub's advice for a secondary rate limit that names no wait.
SECONDARY_RATE_LIMIT_WAIT = 60
COMMENT_MARKER = "<!-- triage-linked-issues:author={login} pr={pr_number} -->"

logger = logging.getLogger("triage_linked_issues")

ISSUE_FIELDS = """
    number
    state
    repository { nameWithOwner }
    labels(first: 50) { nodes { name } }
    assignees(first: 10) { nodes { login } }
    closedByPullRequestsReferences(first: 10, includeClosedPrs: false) {
      nodes { number state repository { nameWithOwner } author { login __typename } }
    }
"""

PULL_REQUEST_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      number
      state
      author { login __typename }
      closingIssuesReferences(first: 25) {
        nodes { %s }
      }
    }
  }
}
""" % ISSUE_FIELDS

SEARCH_QUERY = """
query($search: String!, $after: String) {
  search(type: ISSUE, query: $search, first: 50, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes { ... on Issue { %s } }
  }
}
""" % ISSUE_FIELDS

HISTORY_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    issue(number: $number) {
      timelineItems(last: 100, itemTypes: [ASSIGNED_EVENT, UNLABELED_EVENT]) {
        nodes {
          ... on AssignedEvent { actor { login } assignee { ... on User { login } } }
          ... on UnlabeledEvent { actor { login } label { name } }
        }
      }
    }
  }
}
"""


class GraphQLError(Exception):
    """GitHub answered a GraphQL request with errors (in an HTTP 200)."""


def make_session(retry: Retry) -> requests.Session:
    session = requests.Session()
    session.headers.update(HEADERS)
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


# Every write except the comment is idempotent (adding a label or assignee that
# is already there, or removing one that is gone), so it is safe to retry on
# server errors. Rate limiting is retried by send().
SESSION = make_session(Retry(
    total=3, backoff_factor=2, status_forcelist=(500, 502, 503, 504),
    allowed_methods=None, raise_on_status=False,
))
# A comment POST that failed with a server error may still have been created,
# so it is retried only when the connection never got through, or (by send())
# when GitHub rejected it outright for rate limiting.
COMMENT_SESSION = make_session(Retry(total=3, connect=3, read=0, status=0, backoff_factor=2))


def rate_limit_wait(response: requests.Response):
    """Seconds GitHub asks us to wait before retrying, or None if not rate limited.

    GitHub reports rate limiting as a 429 or as a 403: with Retry-After, with
    X-RateLimit-Remaining at 0 (primary limit), or with a "secondary rate
    limit" message and no header.
    """
    if response.status_code not in (403, 429):
        return None
    retry_after = response.headers.get("Retry-After", "")
    if retry_after.isdigit():
        return float(retry_after)
    if response.headers.get("X-RateLimit-Remaining") == "0":
        reset = response.headers.get("X-RateLimit-Reset", "")
        return max(0.0, float(reset) - time.time()) + 1 if reset.isdigit() else SECONDARY_RATE_LIMIT_WAIT
    if response.status_code == 429 or "rate limit" in response.text.lower():
        return SECONDARY_RATE_LIMIT_WAIT
    return None


def send(method: str, url: str, session: requests.Session = SESSION,
         timeout: int = REST_TIMEOUT, **kwargs) -> requests.Response:
    """Make a request, waiting out and retrying rate limiting. Does not raise on HTTP errors."""
    for attempt in range(RATE_LIMIT_RETRIES + 1):
        response = session.request(method, url, timeout=timeout, **kwargs)
        wait = rate_limit_wait(response)
        if wait is None or attempt == RATE_LIMIT_RETRIES or wait > RATE_LIMIT_MAX_WAIT:
            return response
        logger.warning("%s %s rate limited (%d), retrying in %.0fs.", method, url, response.status_code, wait)
        time.sleep(wait)
    return response


def is_bot(login: str) -> bool:
    return login.lower().removesuffix("[bot]") == BOT_LOGIN.lower().removesuffix("[bot]")


def graphql(query: str, variables: dict) -> dict:
    response = send("POST", f"{API_URL}/graphql", timeout=GRAPHQL_TIMEOUT,
                    json={"query": query, "variables": variables})
    response.raise_for_status()
    payload = response.json()
    if payload.get("errors"):
        raise GraphQLError(f"GraphQL query failed: {payload['errors']}")
    return payload["data"]


def rest(method: str, path: str, session: requests.Session = SESSION, **kwargs) -> requests.Response:
    response = send(method, f"{API_URL}{path}", session=session, **kwargs)
    response.raise_for_status()
    return response


def issue_path(issue_number: int) -> str:
    return f"/repos/{GITHUB_REPOSITORY}/issues/{issue_number}"


def label_names(issue: dict) -> set:
    return {label["name"] for label in issue["labels"]["nodes"]}


def assignee_logins(issue: dict) -> dict:
    """The issue's assignees, keyed by lower-cased login."""
    return {assignee["login"].lower(): assignee["login"] for assignee in issue["assignees"]["nodes"]}


def in_this_repo(node: dict) -> bool:
    return node["repository"]["nameWithOwner"].lower() == GITHUB_REPOSITORY.lower()


def open_linking_prs(issue: dict, exclude_pr: int = 0) -> list:
    """The open PRs in this repository that link the issue, oldest first."""
    return sorted(
        (pull_request for pull_request in issue["closedByPullRequestsReferences"]["nodes"]
         if in_this_repo(pull_request) and pull_request["state"] == "OPEN"
         and pull_request["number"] != exclude_pr),
        key=lambda pull_request: pull_request["number"],
    )


def user_login(author: dict) -> str:
    """The author's login if it is a user; "" for bots (dependabot, ...) and deleted accounts."""
    return author.get("login", "") if author.get("__typename") == "User" else ""


def ensure_auto_triaged_label() -> None:
    response = send("GET", f"{API_URL}/repos/{GITHUB_REPOSITORY}/labels/{AUTO_TRIAGED_LABEL}")
    if response.status_code != 404:
        response.raise_for_status()
        return
    logger.info("Creating missing label '%s'.", AUTO_TRIAGED_LABEL)
    if DRY_RUN:
        return
    response = send(
        "POST", f"{API_URL}/repos/{GITHUB_REPOSITORY}/labels",
        json={"name": AUTO_TRIAGED_LABEL, "color": AUTO_TRIAGED_COLOR,
              "description": "Triaged automatically because a pull request is linked to fix it"},
    )
    # 422 is "already_exists": another run created it in the meantime.
    if response.status_code != 422:
        response.raise_for_status()


def issue_history(issue_number: int) -> tuple:
    """Return (bot_assignees, rejected) from the issue's timeline.

    bot_assignees: lower-cased logins whose most recent assignment was made by
    this script. rejected: whether anyone other than this script has removed
    TRIAGED_LABEL from the issue.
    """
    owner, name = GITHUB_REPOSITORY.split("/", 1)
    data = graphql(HISTORY_QUERY, {"owner": owner, "name": name, "number": issue_number})
    assigned_by = {}
    rejected = False
    for event in data["repository"]["issue"]["timelineItems"]["nodes"]:
        actor = (event.get("actor") or {}).get("login") or ""
        if "assignee" in event:
            assignee = ((event.get("assignee") or {}).get("login") or "").lower()
            if assignee:
                assigned_by[assignee] = actor
        elif (event.get("label") or {}).get("name") == TRIAGED_LABEL and not is_bot(actor):
            rejected = True
    return {login for login, actor in assigned_by.items() if is_bot(actor)}, rejected


def can_be_assigned(issue_number: int, login: str) -> bool:
    """Whether GitHub allows `login` to be assigned to this issue.

    Assigning someone GitHub does not allow does not fail: it drops them and
    still returns 201, hence the explicit check.
    """
    response = send("GET", f"{API_URL}{issue_path(issue_number)}/assignees/{login}")
    if response.status_code == 404:
        return False
    response.raise_for_status()
    return True


def already_commented(issue_number: int, login: str) -> bool:
    """Whether this script already posted its comment about `login` on the issue."""
    # Cut before "pr=", keeping the space that ends the login, so that
    # "author=foo " does not match "author=foobar ".
    marker_prefix = COMMENT_MARKER.split("pr=", 1)[0].format(login=login)
    url = f"{API_URL}{issue_path(issue_number)}/comments?per_page=100"
    while url:
        response = send("GET", url)
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


def plan_assignment(issue: dict, login: str) -> tuple:
    """Return (assign, comment): how to give the issue to `login` ("" for nobody)."""
    if not login or login.lower() in assignee_logins(issue):
        return False, False
    assign = can_be_assigned(issue["number"], login)
    comment = not assign and not already_commented(issue["number"], login)
    return assign, comment


def describe_assignment(login: str, assign: bool, comment: bool) -> list:
    return ([f"assign @{login}"] if assign else []) + ([f"comment for @{login} (cannot be assigned)"] if comment else [])


def apply_assignment(issue_number: int, pr_number: int, login: str, assign: bool, comment: bool) -> None:
    if assign:
        result = rest("POST", f"{issue_path(issue_number)}/assignees", json={"assignees": [login]}).json()
        # Checked before, but GitHub drops an unassignable user silently
        # rather than failing, so fall back to the comment if it did.
        if login.lower() not in {assignee["login"].lower() for assignee in result.get("assignees", [])}:
            logger.warning("GitHub did not assign issue #%s to @%s.", issue_number, login)
            comment = not already_commented(issue_number, login)
    if comment:
        rest("POST", f"{issue_path(issue_number)}/comments", session=COMMENT_SESSION,
             json={"body": unassignable_comment(pr_number, login)})


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
    if issue_history(issue_number)[1]:
        logger.info("PR #%s links issue #%s, but '%s' was removed from it by hand; skipping.",
                    pr_number, issue_number, TRIAGED_LABEL)
        return False

    # Bot-authored PRs (dependabot, ...) label what they fix but assign no one.
    login = user_login(author)
    assign, comment = plan_assignment(issue, login)
    actions = [f"label '{TRIAGED_LABEL}', '{AUTO_TRIAGED_LABEL}'"] + describe_assignment(login, assign, comment)
    logger.info("PR #%s links issue #%s: %s.", pr_number, issue_number, ", ".join(actions))
    if DRY_RUN:
        return True

    apply_assignment(issue_number, pr_number, login, assign, comment)
    # Labelled last: the label is what marks the issue as handled, so a
    # failure above leaves it to be retried by the next run.
    rest("POST", f"{issue_path(issue_number)}/labels", json={"labels": [TRIAGED_LABEL, AUTO_TRIAGED_LABEL]})
    return True


def reconcile_issue(issue: dict, closed_pr: int = 0) -> bool:
    """Bring an automatic triage in line with the issue's current links. Returns True when it changed.

    With no open PR linking the issue, both labels are removed and the bot's
    assignees unassigned. Otherwise the bot's assignees who no longer author
    a linking PR are unassigned, and if that leaves no linking PR's author
    assigned, the issue passes to the author of the oldest linking PR.
    `closed_pr` is a PR just closed unmerged, never counted as linking.
    """
    issue_number = issue["number"]
    if not in_this_repo(issue) or issue["state"] != "OPEN":
        return False
    # Without AUTO_TRIAGED_LABEL the triage was a human's, or a human confirmed it.
    if AUTO_TRIAGED_LABEL not in label_names(issue):
        return False

    pull_requests = open_linking_prs(issue, exclude_pr=closed_pr)
    authors = {user_login(pr.get("author") or {}).lower() for pr in pull_requests} - {""}
    assignees = assignee_logins(issue)
    stale = [assignee for key, assignee in assignees.items() if key not in authors]
    if stale:
        bot_assignees = issue_history(issue_number)[0]
        stale = [assignee for assignee in stale if assignee.lower() in bot_assignees]

    # Hand over only an assignment the bot is taking away, so an issue a
    # human unassigned is not reassigned.
    successor = None
    login = ""
    assign = comment = False
    if pull_requests and stale and not authors & assignees.keys():
        successor = pull_requests[0]
        login = user_login(successor.get("author") or {})
        assign, comment = plan_assignment(issue, login)

    actions = [] if pull_requests else [f"remove '{TRIAGED_LABEL}', '{AUTO_TRIAGED_LABEL}'"]
    actions += [f"unassign @{assignee}" for assignee in stale] + describe_assignment(login, assign, comment)
    if not actions:
        return False
    if pull_requests:
        reason = "linked from #" + ", #".join(str(pull_request["number"]) for pull_request in pull_requests)
    else:
        reason = "no open pull request links it"
    logger.info("Issue #%s (%s): %s.", issue_number, reason, ", ".join(actions))
    if DRY_RUN:
        return True

    path = issue_path(issue_number)
    # The new assignment goes first and the labels come off last, so a failure
    # part way leaves the issue in a state the next run picks up again.
    if successor:
        apply_assignment(issue_number, successor["number"], login, assign, comment)
    if stale:
        rest("DELETE", f"{path}/assignees", json={"assignees": stale})
    if not pull_requests:
        for label in (TRIAGED_LABEL, AUTO_TRIAGED_LABEL):
            response = send("DELETE", f"{API_URL}{path}/labels/{label}")
            if response.status_code != 404:
                response.raise_for_status()
    return True


def handle_issue(handler, issue: dict, *args) -> tuple:
    """Run `handler` on one issue, isolating failures. Returns (changed, failed)."""
    try:
        return int(handler(issue, *args)), 0
    except (requests.RequestException, GraphQLError) as exc:
        logger.error("Issue #%s: %s", issue["number"], exc)
        return 0, 1


def handle_pull_request(pr_number: int) -> int:
    owner, name = GITHUB_REPOSITORY.split("/", 1)
    data = graphql(PULL_REQUEST_QUERY, {"owner": owner, "name": name, "number": pr_number})
    pull_request = data["repository"]["pullRequest"]
    if not pull_request:
        raise SystemExit(f"PR #{pr_number} not found in {GITHUB_REPOSITORY}")

    author = pull_request.get("author") or {}
    # Only the PR's current links: one removed earlier is reconciled by the scan.
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
            result = handle_issue(reconcile_issue, issue, pr_number)
            changed, failed = changed + result[0], failed + result[1]
    else:
        logger.info("PR #%s is merged; nothing to do.", pr_number)
    logger.info("PR #%s (%s): changed %d linked issues.", pr_number, pull_request["state"].lower(), changed)
    return failed


def search_issues(search: str) -> list:
    """Every issue matching `search` (up to SCAN_LIMIT), fetched before any is changed.

    Search cursors are offsets, and changing an issue's labels can move it out
    of the results, so processing page by page would skip issues.
    """
    issues = []
    after = None
    while True:
        page = graphql(SEARCH_QUERY, {"search": search, "after": after})["search"]
        issues.extend(issue for issue in page["nodes"] if issue)
        if (SCAN_LIMIT and len(issues) >= SCAN_LIMIT) or not page["pageInfo"]["hasNextPage"]:
            break
        after = page["pageInfo"]["endCursor"]
    if SCAN_LIMIT and len(issues) > SCAN_LIMIT:
        logger.info("Limiting to the first %d matching issues (SCAN_LIMIT).", SCAN_LIMIT)
        issues = issues[:SCAN_LIMIT]
    return issues


def scan() -> int:
    ensure_auto_triaged_label()
    failed = 0

    # Undo or hand over automatic triages whose links changed without a PR
    # event: a closing keyword edited out, or a sidebar link removed.
    search = f'repo:{GITHUB_REPOSITORY} is:issue is:open label:"{AUTO_TRIAGED_LABEL}"'
    logger.info("Reconciling: %s", search)
    issues = search_issues(search)
    changed = 0
    for issue in issues:
        result = handle_issue(reconcile_issue, issue)
        changed, failed = changed + result[0], failed + result[1]
    logger.info("Reconciled %d issues, changed %d.", len(issues), changed)

    search = f'repo:{GITHUB_REPOSITORY} is:issue is:open linked:pr -label:"{TRIAGED_LABEL}"'
    logger.info("Scanning: %s", search)
    issues = search_issues(search)
    changed = 0
    for issue in issues:
        pull_requests = open_linking_prs(issue)
        if not pull_requests:
            continue
        # Triaged for the earliest open PR in this repository that links it.
        pull_request = pull_requests[0]
        result = handle_issue(triage_issue, issue, pull_request["number"], pull_request.get("author") or {})
        changed, failed = changed + result[0], failed + result[1]
    logger.info("Scanned %d issues, triaged %d.", len(issues), changed)
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

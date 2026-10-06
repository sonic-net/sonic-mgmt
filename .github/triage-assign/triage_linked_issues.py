"""Mark issues as triaged once a pull request is linked to fix them.

An issue counts as linked when GitHub lists it in the pull request's
`closingIssuesReferences`: the PR description says "Fixes #123" / "Closes #123"
(or another closing keyword), or the issue was linked from the PR's
Development sidebar. These are the issues GitHub shows as linked on the issue
page, and closes when the PR merges.

For every such issue that is open, in this repository and not yet labelled
TRIAGED_LABEL (default "Triaged"), the script:
  * adds the TRIAGED_LABEL label, and
  * assigns the issue to the pull request author or, when GitHub will not let
    them be assigned (they are not a sonic-net member or collaborator), posts a
    comment on the issue mentioning them instead.

Issues that already carry the label are left alone, which also keeps the
hourly scan from repeating itself.

GitHub fires no workflow event when an issue is linked, so the workflow runs
when a PR is opened, reopened or edited (which covers closing keywords added to
the description), and on a schedule (which covers links made from the sidebar).

Modes:
  PR_NUMBER set   -> handle that single pull request
  PR_NUMBER unset -> scan every open pull request
"""

import os
import sys

import requests

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
GITHUB_REPOSITORY = os.environ["GITHUB_REPOSITORY"]
PR_NUMBER = os.environ.get("PR_NUMBER", "").strip()

TRIAGED_LABEL = os.environ.get("TRIAGED_LABEL", "").strip() or "Triaged"
DRY_RUN = os.environ.get("DRY_RUN", "false").strip().lower() in ("true", "t", "1", "yes", "y", "on")
SCAN_LIMIT = int(os.environ.get("SCAN_LIMIT", "0"))

API_URL = os.environ.get("GITHUB_API_URL", "https://api.github.com")
HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

PULL_REQUEST_FIELDS = """
    number
    author { login __typename }
    closingIssuesReferences(first: 25) {
      nodes {
        number
        state
        repository { nameWithOwner }
        labels(first: 100) { nodes { name } }
        assignees(first: 20) { nodes { login } }
      }
    }
"""

SINGLE_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) { %s }
  }
}
""" % PULL_REQUEST_FIELDS

SCAN_QUERY = """
query($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(states: OPEN, first: 50, after: $after, orderBy: {field: CREATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes { %s }
    }
  }
}
""" % PULL_REQUEST_FIELDS


def graphql(query: str, variables: dict) -> dict:
    response = requests.post(
        f"{API_URL}/graphql", json={"query": query, "variables": variables}, headers=HEADERS, timeout=60
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("errors"):
        raise SystemExit(f"GraphQL query failed: {payload['errors']}")
    return payload["data"]


def rest_post(path: str, body: dict) -> dict:
    response = requests.post(f"{API_URL}{path}", json=body, headers=HEADERS, timeout=30)
    response.raise_for_status()
    return response.json()


def can_be_assigned(issue_number: int, login: str) -> bool:
    """Whether GitHub allows `login` to be assigned to this issue.

    Assignees are limited to sonic-net members, repository collaborators and
    people who have commented on the issue. Assigning anyone else does not
    fail: GitHub drops them and still returns 201, hence the explicit check.
    """
    response = requests.get(
        f"{API_URL}/repos/{GITHUB_REPOSITORY}/issues/{issue_number}/assignees/{login}", headers=HEADERS, timeout=30
    )
    if response.status_code == 404:
        return False
    response.raise_for_status()
    return True


def unassignable_comment(pr_number: int, login: str) -> str:
    return (
        f"@{login} is working on this issue in #{pr_number}.\n\n"
        "GitHub does not allow this issue to be assigned to them automatically (assignees must be "
        "members of the sonic-net organization or collaborators on this repository)."
    )


def triage_issues(pull_request: dict) -> int:
    """Triage the issues `pull_request` is linked to. Returns how many were changed."""
    number = pull_request["number"]
    author = pull_request.get("author") or {}
    login = author.get("login", "")
    # Bots (dependabot, mssonicbld's cherry-picks, ...) cannot be assigned
    # issues; still label what they fix.
    is_user = bool(login) and author.get("__typename") == "User"

    changed = 0
    for issue in pull_request["closingIssuesReferences"]["nodes"]:
        issue_ref = f"{issue['repository']['nameWithOwner']}#{issue['number']}"
        # A PR may close issues in other repositories, which this token cannot
        # modify; closed issues need no triage.
        if issue["repository"]["nameWithOwner"].lower() != GITHUB_REPOSITORY.lower():
            print(f"PR #{number}: {issue_ref} is in another repository, skipping.")
            continue
        if issue["state"] != "OPEN":
            continue
        if TRIAGED_LABEL in {label["name"] for label in issue["labels"]["nodes"]}:
            continue

        issue_number = issue["number"]
        assignees = {assignee["login"].lower() for assignee in issue["assignees"]["nodes"]}
        assign = is_user and login.lower() not in assignees and can_be_assigned(issue_number, login)
        comment = is_user and login.lower() not in assignees and not assign

        actions = [f"label '{TRIAGED_LABEL}'"]
        if assign:
            actions.append(f"assign @{login}")
        if comment:
            actions.append(f"comment for @{login} (cannot be assigned)")
        print(f"PR #{number} links issue #{issue_number}: {', '.join(actions)}.")
        changed += 1
        if DRY_RUN:
            continue

        issue_path = f"/repos/{GITHUB_REPOSITORY}/issues/{issue_number}"
        if assign:
            result = rest_post(f"{issue_path}/assignees", {"assignees": [login]})
            # Checked above, but GitHub drops an unassignable user silently
            # rather than failing, so fall back to the comment if it did.
            if login.lower() not in {assignee["login"].lower() for assignee in result.get("assignees", [])}:
                print(f"WARNING: GitHub did not assign issue #{issue_number} to @{login}.", file=sys.stderr)
                comment = True
        if comment:
            rest_post(f"{issue_path}/comments", {"body": unassignable_comment(number, login)})
        # Labelled last: the label is what marks the issue as handled, so a
        # failure above leaves it to be retried by the next run.
        rest_post(f"{issue_path}/labels", {"labels": [TRIAGED_LABEL]})
    return changed


def main() -> None:
    owner, name = GITHUB_REPOSITORY.split("/", 1)

    if PR_NUMBER:
        data = graphql(SINGLE_QUERY, {"owner": owner, "name": name, "number": int(PR_NUMBER)})
        pull_request = data["repository"]["pullRequest"]
        if not pull_request:
            raise SystemExit(f"PR #{PR_NUMBER} not found in {GITHUB_REPOSITORY}")
        triage_issues(pull_request)
        return

    print("Scanning open pull requests for linked issues...")
    scanned = 0
    changed = 0
    after = None
    while True:
        data = graphql(SCAN_QUERY, {"owner": owner, "name": name, "after": after})
        page = data["repository"]["pullRequests"]
        for pull_request in page["nodes"]:
            if SCAN_LIMIT and scanned >= SCAN_LIMIT:
                print(f"Reached SCAN_LIMIT of {SCAN_LIMIT} pull requests, stopping.")
                print(f"Scanned {scanned} open pull requests, triaged {changed} linked issues.")
                return
            scanned += 1
            changed += triage_issues(pull_request)
        if not page["pageInfo"]["hasNextPage"]:
            break
        after = page["pageInfo"]["endCursor"]

    print(f"Scanned {scanned} open pull requests, triaged {changed} linked issues.")


if __name__ == "__main__":
    main()

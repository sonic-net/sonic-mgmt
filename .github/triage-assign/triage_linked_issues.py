"""Mark issues as triaged once a pull request is linked to fix them.

An issue counts as linked when GitHub lists it in the pull request's
`closingIssuesReferences`: the PR description says "Fixes #123" / "Closes #123"
(or another closing keyword), or the issue was linked from the PR's
Development sidebar. These are the issues GitHub shows as linked on the issue
page, and closes when the PR merges.

For every such issue that is open and in this repository, the script:
  * adds the TRIAGED_LABEL label (default "Triaged"), and
  * assigns the issue to the pull request author.

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


def triage_issues(pull_request: dict) -> int:
    """Triage the issues `pull_request` is linked to. Returns how many were changed."""
    number = pull_request["number"]
    author = pull_request.get("author") or {}
    login = author.get("login", "")
    # Bots (dependabot, mssonicbld's cherry-picks, ...) cannot be assigned
    # issues; still label what they fix.
    assignable = bool(login) and author.get("__typename") == "User"

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

        labels = {label["name"] for label in issue["labels"]["nodes"]}
        assignees = {assignee["login"].lower() for assignee in issue["assignees"]["nodes"]}
        add_label = TRIAGED_LABEL not in labels
        add_assignee = assignable and login.lower() not in assignees
        if not add_label and not add_assignee:
            continue

        actions = []
        if add_label:
            actions.append(f"label '{TRIAGED_LABEL}'")
        if add_assignee:
            actions.append(f"assign @{login}")
        print(f"PR #{number} links issue #{issue['number']}: {', '.join(actions)}.")
        changed += 1
        if DRY_RUN:
            continue

        issue_path = f"/repos/{GITHUB_REPOSITORY}/issues/{issue['number']}"
        if add_label:
            rest_post(f"{issue_path}/labels", {"labels": [TRIAGED_LABEL]})
        if add_assignee:
            # GitHub silently drops assignees who cannot be assigned here
            # (outside contributors who have not commented on the issue), so
            # check the result rather than trusting the 201.
            result = rest_post(f"{issue_path}/assignees", {"assignees": [login]})
            if login.lower() not in {assignee["login"].lower() for assignee in result.get("assignees", [])}:
                print(
                    f"WARNING: GitHub did not assign issue #{issue['number']} to @{login} "
                    "(probably not an assignable user in this repository).",
                    file=sys.stderr,
                )
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

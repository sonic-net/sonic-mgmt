"""
Automated PR review script for sonic-net/sonic-mgmt.

This script finds all open PRs filed in the last N days (default: 3),
reviews each one against the standard PR template requirements, and
posts a comment summarizing any missing or incomplete sections.

A comment is only posted once per PR (idempotent: won't re-comment if
the bot has already reviewed this PR).

Required environment variables:
  GITHUB_TOKEN     - GitHub token with read/write access to pull requests
  GITHUB_REPOSITORY - Repository in "owner/repo" format (set by GitHub Actions)

Optional environment variables:
  DAYS_BACK        - Number of days to look back (default: 3)
"""

import os
import re
from datetime import datetime, timezone, timedelta

from github import Auth, Github

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    raise SystemExit(
        "ERROR: GITHUB_TOKEN environment variable is not set. "
        "Set it to a GitHub token with 'pull-requests: write' permission."
    )
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "sonic-net/sonic-mgmt")
DAYS_BACK = int(os.environ.get("DAYS_BACK", "3"))

BOT_COMMENT_MARKER = "<!-- pr-auto-review-bot -->"

# ---------------------------------------------------------------------------
# PR template section checks
# ---------------------------------------------------------------------------

# Checklist items that indicate an unchecked checkbox in markdown
_UNCHECKED_RE = re.compile(r"^\s*-\s*\[\s*\]", re.MULTILINE)
_CHECKED_RE = re.compile(r"^\s*-\s*\[x\]", re.MULTILINE | re.IGNORECASE)

# Placeholder text that indicates sections were never filled in
_PLACEHOLDER_PATTERNS = [
    r"^\s*Summary:\s*$",
    r"Fixes\s*#\s*\(issue\)",
]


def _section_has_content(body: str, heading: str) -> bool:
    """Return True if the section following *heading* has non-trivial content."""
    # Match from the heading to the next heading or end of string
    pattern = re.compile(
        r"(?:^|\n)" + re.escape(heading) + r"\s*\n(.*?)(?=\n#+\s|\Z)",
        re.DOTALL | re.IGNORECASE,
    )
    match = pattern.search(body)
    if not match:
        return False
    content = match.group(1).strip()
    # Strip HTML comments
    content = re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL).strip()
    return bool(content)


def review_pr_body(body: str) -> list[str]:
    """
    Review a PR body against the template requirements.

    Args:
        body: The raw markdown text of the PR description.

    Returns a list of human-readable issue strings.  An empty list means the
    PR body looks complete.
    """
    issues = []

    if not body or not body.strip():
        return ["PR description is empty. Please fill in the PR template."]

    # 1. Description / Summary section
    if not _section_has_content(body, "### Description of PR"):
        issues.append(
            "**Missing description**: The `### Description of PR` section appears "
            "to be empty or only contains the placeholder text. "
            "Please summarize the change and reference any related issues."
        )
    else:
        # Check for unfilled placeholder lines inside the description
        for pattern in _PLACEHOLDER_PATTERNS:
            if re.search(pattern, body, re.MULTILINE):
                issues.append(
                    "**Incomplete description**: The `Summary:` line or "
                    "`Fixes # (issue)` placeholder has not been updated. "
                    "Please fill in the actual values."
                )
                break

    # 2. Type of change – at least one box must be checked
    type_section_match = re.search(
        r"### Type of change\s*\n(.*?)(?=\n###|\Z)", body, re.DOTALL | re.IGNORECASE
    )
    if type_section_match:
        type_section = type_section_match.group(1)
        if not _CHECKED_RE.search(type_section):
            issues.append(
                "**No type of change selected**: Please check at least one option "
                "under `### Type of change` (Bug fix, New Test case, etc.)."
            )
    else:
        issues.append(
            "**Missing `### Type of change` section**: This section is required "
            "by the PR template."
        )

    # 3. Approach section – motivation sub-heading
    if not _section_has_content(body, "#### What is the motivation for this PR?"):
        issues.append(
            "**Missing motivation**: Please describe the motivation for this change "
            "under `#### What is the motivation for this PR?`."
        )

    # 4. How did you do it?
    if not _section_has_content(body, "#### How did you do it?"):
        issues.append(
            "**Missing implementation details**: Please describe the implementation "
            "under `#### How did you do it?`."
        )

    # 5. How did you verify/test it?
    if not _section_has_content(body, "#### How did you verify/test it?"):
        issues.append(
            "**Missing verification details**: Please describe how this was tested "
            "under `#### How did you verify/test it?`."
        )

    return issues


def build_comment(pr_number: int, issues: list[str]) -> str:
    """Build the markdown comment body."""
    if not issues:
        lines = [
            BOT_COMMENT_MARKER,
            f"## :white_check_mark: Automated PR Review — PR #{pr_number}",
            "",
            "The PR description looks complete. Thank you for filling in all the "
            "required sections! :tada:",
            "",
            "> *This comment was generated automatically by the PR review bot.*",
        ]
    else:
        issue_list = "\n".join(f"- {issue}" for issue in issues)
        lines = [
            BOT_COMMENT_MARKER,
            f"## :memo: Automated PR Review — PR #{pr_number}",
            "",
            "Hi! The automated PR review found the following items that need "
            "attention:",
            "",
            issue_list,
            "",
            "Please update the PR description to address these points so that "
            "reviewers have all the context they need.",
            "",
            "> *This comment was generated automatically by the PR review bot. "
            "If you believe this is a false positive, please update the description "
            "or ignore this comment.*",
        ]
    return "\n".join(lines)


def already_reviewed(pr) -> bool:
    """Return True if the bot has already posted a review comment on this PR."""
    return any(
        BOT_COMMENT_MARKER in (comment.body or "")
        for comment in pr.get_issue_comments()
    )


def main():
    auth = Auth.Token(GITHUB_TOKEN)
    g = Github(auth=auth)
    repo = g.get_repo(GITHUB_REPOSITORY)

    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=DAYS_BACK)
    print(f"Reviewing open PRs created after {cutoff.isoformat()} "
          f"(last {DAYS_BACK} days) in {GITHUB_REPOSITORY}")

    reviewed = 0
    skipped = 0

    for pr in repo.get_pulls(state="open", sort="created", direction="desc"):
        created_at = pr.created_at
        # GitHub returns naive datetimes; make them timezone-aware
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        if created_at < cutoff:
            # PRs are sorted newest-first; once we go past the cutoff we're done
            break

        print(f"  Reviewing PR #{pr.number}: {pr.title!r} "
              f"(created {created_at.isoformat()})")

        if already_reviewed(pr):
            print(f"    -> Already reviewed, skipping.")
            skipped += 1
            continue

        issues = review_pr_body(pr.body or "")
        comment_body = build_comment(pr.number, issues)

        pr.create_issue_comment(comment_body)
        status = "issues found" if issues else "looks good"
        print(f"    -> Posted comment ({status}, {len(issues)} item(s)).")
        reviewed += 1

    print(f"\nDone. Reviewed {reviewed} PR(s), skipped {skipped} (already reviewed).")


if __name__ == "__main__":
    main()

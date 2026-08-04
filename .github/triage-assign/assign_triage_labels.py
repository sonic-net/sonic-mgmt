"""Assign per-company triage labels to pull requests.

Each pull request is labelled with `assignments_per_pr` company labels drawn at
random from the companies configured in companies.yml, excluding the company
the PR author belongs to.

The draw is seeded from the repository name and the PR number, so it needs no
persistent state: the same PR always yields the same companies, which makes the
backstop scan idempotent, while the distribution across PRs stays even.

Author company is resolved in this order:
  1. the `overrides` map in companies.yml
  2. contributors.json from sonic-net/sonic-contributor-map (best effort; that
     repository is private, so this needs CONTRIBUTOR_MAP_TOKEN to be set)
  3. a username suffix heuristic (e.g. "someone-arista" -> Arista)

Modes:
  PR_NUMBER set  -> label that single pull request
  PR_NUMBER unset -> scan open pull requests and label the ones that carry no
                     company label yet
"""

import hashlib
import json
import os
import random
import sys
import urllib.error
import urllib.request

import yaml

from github import Auth, Github

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
GITHUB_REPOSITORY = os.environ["GITHUB_REPOSITORY"]
PR_NUMBER = os.environ.get("PR_NUMBER", "").strip()

CONFIG_PATH = os.environ.get("TRIAGE_CONFIG_PATH", ".github/triage-assign/companies.yml")
CONTRIBUTOR_MAP_TOKEN = os.environ.get("CONTRIBUTOR_MAP_TOKEN", "").strip()
CONTRIBUTOR_MAP_URL = os.environ.get(
    "CONTRIBUTOR_MAP_URL",
    "https://api.github.com/repos/sonic-net/sonic-contributor-map/contents/contributors.json",
)
DRY_RUN = os.environ.get("DRY_RUN", "false").strip().lower() in ("true", "t", "1", "yes", "y", "on")
SCAN_LIMIT = int(os.environ.get("SCAN_LIMIT", "0"))

DEFAULT_LABEL_COLOR = "c5def5"


def load_config(config_path: str) -> dict:
    with open(config_path, "r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file) or {}

    companies = config.get("companies") or []
    if len(companies) < 2:
        raise SystemExit(f"{config_path}: at least two companies must be configured")

    return {
        "label_prefix": str(config.get("label_prefix", "triage-")),
        "assignments_per_pr": int(config.get("assignments_per_pr", 2)),
        "companies": [
            {
                "name": str(company["name"]),
                "organizations": [
                    str(org).strip().lower()
                    for org in (company.get("organizations") or [company["name"]])
                ],
                "username_suffixes": [
                    str(suffix).strip().lower()
                    for suffix in (company.get("username_suffixes") or [])
                ],
                "label_color": str(company.get("label_color", DEFAULT_LABEL_COLOR)),
            }
            for company in companies
        ],
        "overrides": {
            str(user).strip().lower(): str(company).strip()
            for user, company in (config.get("overrides") or {}).items()
        },
    }


def load_contributor_map() -> dict[str, set[str]]:
    """Return {github username (lowercase): {organization (lowercase), ...}}.

    Returns an empty map, rather than failing, when the contributor map cannot
    be read: it is a best-effort input and the suffix heuristic covers for it.
    """
    if not CONTRIBUTOR_MAP_TOKEN:
        print(
            "NOTE: CONTRIBUTOR_MAP_TOKEN is not set; sonic-contributor-map is a private "
            "repository, so falling back to the username suffix heuristic.",
            file=sys.stderr,
        )
        return {}

    request = urllib.request.Request(
        CONTRIBUTOR_MAP_URL,
        headers={
            "Authorization": f"Bearer {CONTRIBUTOR_MAP_TOKEN}",
            "Accept": "application/vnd.github.raw+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "sonic-mgmt-triage-assign",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            contributors = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError) as exc:
        print(
            f"WARNING: could not read {CONTRIBUTOR_MAP_URL} ({exc}); falling back to the "
            "username suffix heuristic.",
            file=sys.stderr,
        )
        return {}

    contributor_map: dict[str, set[str]] = {}
    for entry in contributors:
        if not isinstance(entry, dict):
            continue
        user = str(entry.get("Id", "")).strip().lower()
        organization = str(entry.get("Organization", "")).strip().lower()
        if user and organization:
            contributor_map.setdefault(user, set()).add(organization)

    print(f"Loaded {len(contributor_map)} contributors from the contributor map.")
    return contributor_map


def author_companies(author: str, config: dict, contributor_map: dict[str, set[str]]) -> set[str]:
    """Companies the PR author belongs to, and so must not be assigned to."""
    author_key = author.strip().lower()
    companies = config["companies"]

    override = config["overrides"].get(author_key)
    if override:
        matched = {company["name"] for company in companies if company["name"] == override}
        if matched:
            return matched
        print(f"WARNING: override for '{author}' names unknown company '{override}'.", file=sys.stderr)

    organizations = contributor_map.get(author_key, set())
    if organizations:
        matched = {
            company["name"]
            for company in companies
            if organizations.intersection(company["organizations"])
        }
        # The author is in the map: trust it even when their organization is
        # not one of the configured companies (an empty result is meaningful).
        return matched

    return {
        company["name"]
        for company in companies
        if any(author_key.endswith(suffix) for suffix in company["username_suffixes"])
    }


def pick_companies(repository: str, pr_number: int, candidates: list[str], count: int) -> list[str]:
    """Deterministically draw `count` companies for this PR, without state."""
    seed = int.from_bytes(hashlib.sha256(f"{repository}#{pr_number}".encode("utf-8")).digest(), "big")
    return sorted(random.Random(seed).sample(sorted(candidates), min(count, len(candidates))))


def ensure_labels_exist(repo, config: dict) -> None:
    existing = {label.name for label in repo.get_labels()}
    for company in config["companies"]:
        name = f"{config['label_prefix']}{company['name']}"
        if name not in existing:
            print(f"Creating missing label '{name}'.")
            if not DRY_RUN:
                repo.create_label(name=name, color=company["label_color"])


def assign_labels(repo, pull_request, config: dict, contributor_map: dict[str, set[str]]) -> bool:
    """Label a single pull request. Returns True when labels were assigned."""
    prefix = config["label_prefix"]
    company_labels = {f"{prefix}{company['name']}" for company in config["companies"]}

    already_assigned = {label.name for label in pull_request.labels}.intersection(company_labels)
    if already_assigned:
        print(f"PR #{pull_request.number}: already labelled ({', '.join(sorted(already_assigned))}), skipping.")
        return False

    author = pull_request.user.login if pull_request.user else ""
    if not author:
        print(f"PR #{pull_request.number}: no author, skipping.", file=sys.stderr)
        return False

    excluded = author_companies(author, config, contributor_map)
    candidates = [company["name"] for company in config["companies"] if company["name"] not in excluded]

    if len(candidates) < config["assignments_per_pr"]:
        print(
            f"PR #{pull_request.number}: only {len(candidates)} companies remain after excluding "
            f"the author's ({', '.join(sorted(excluded)) or 'none'}); assigning all of them.",
            file=sys.stderr,
        )

    selected = pick_companies(repo.full_name, pull_request.number, candidates, config["assignments_per_pr"])
    if not selected:
        print(f"PR #{pull_request.number}: no eligible company to assign.", file=sys.stderr)
        return False

    labels = [f"{prefix}{name}" for name in selected]
    print(
        f"PR #{pull_request.number} by @{author} "
        f"(author companies: {', '.join(sorted(excluded)) or 'unknown'}) -> {', '.join(labels)}"
    )
    if not DRY_RUN:
        pull_request.add_to_labels(*labels)
    return True


def main() -> None:
    config = load_config(CONFIG_PATH)
    contributor_map = load_contributor_map()

    github = Github(auth=Auth.Token(GITHUB_TOKEN))
    repo = github.get_repo(GITHUB_REPOSITORY)

    ensure_labels_exist(repo, config)

    if PR_NUMBER:
        assign_labels(repo, repo.get_pull(int(PR_NUMBER)), config, contributor_map)
        return

    print("Scanning open pull requests for missing triage labels...")
    scanned = 0
    assigned = 0
    for pull_request in repo.get_pulls(state="open", sort="created", direction="desc"):
        if SCAN_LIMIT and scanned >= SCAN_LIMIT:
            print(f"Reached SCAN_LIMIT of {SCAN_LIMIT} pull requests, stopping.")
            break
        scanned += 1
        if assign_labels(repo, pull_request, config, contributor_map):
            assigned += 1

    print(f"Scanned {scanned} open pull requests, labelled {assigned}.")


if __name__ == "__main__":
    main()

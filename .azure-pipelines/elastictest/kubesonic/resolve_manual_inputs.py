#!/usr/bin/env python3
"""Resolve a guided KubeSonic manual request to immutable execution inputs."""

import difflib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


PROFILE_ROOT = "/tests/k8s_container/kubesonic_profiles"
SUITE_OPTION = "--k8s-container-test"
MANAGEMENT_URL = (
    "https://sonic-elastictest-prod-management-webapp.azurewebsites.net"
    "/api/v1/testbeds/query_by_keyword"
)
DISALLOWED_COMMENT_TAGS = ("aibe test only",)
MAX_ATTEMPTS = 3
RETRYABLE_HTTP_CODES = {408, 429, 500, 502, 503, 504}

_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_NODE_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:@+\[\]=-]*$")
_TOPOLOGY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


class ResolutionError(ValueError):
    """Raised when a request cannot be resolved safely."""


def _required(name):
    value = os.environ.get(name, "")
    if not value:
        raise ResolutionError(f"{name} is required")
    return value


def _request_json(url, token, params=None):
    if params:
        url = f"{url}?{urlencode(params)}"
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    last_failure = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:500]
            failure = ResolutionError(
                f"HTTP {error.code} while reading {url}: {detail}"
            )
            if error.code not in RETRYABLE_HTTP_CODES:
                raise failure from error
            last_failure = (failure, error)
        except (URLError, TimeoutError) as error:
            reason = getattr(error, "reason", error)
            failure = ResolutionError(f"Failed to read {url}: {reason}")
            last_failure = (failure, error)

        if attempt < MAX_ATTEMPTS:
            time.sleep(2 ** (attempt - 1))

    failure, error = last_failure
    raise failure from error


def _repository_url(collection_uri, project_id, repository_id, suffix):
    base = collection_uri.rstrip("/")
    return (
        f"{base}/{project_id}/_apis/git/repositories/"
        f"{repository_id}/{suffix.lstrip('/')}"
    )


def _resolve_pull_request(
    collection_uri, project_id, repository_id, token, pull_request_id
):
    url = _repository_url(
        collection_uri,
        project_id,
        repository_id,
        f"pullRequests/{pull_request_id}",
    )
    pull_request = _request_json(url, token, {"api-version": "7.1"})

    status = pull_request.get("status")
    if status not in ("active", "completed"):
        raise ResolutionError(
            f"PR {pull_request_id} must be active or completed, not {status}"
        )
    if pull_request.get("targetRefName") != "refs/heads/internal":
        raise ResolutionError(
            f"PR {pull_request_id} must target refs/heads/internal"
        )

    source_repository = (pull_request.get("repository") or {}).get("id")
    if (
        source_repository
        and source_repository.lower() != repository_id.lower()
    ):
        raise ResolutionError(
            f"PR {pull_request_id} belongs to repository {source_repository}, "
            f"not {repository_id}"
        )

    commit_field = (
        "lastMergeSourceCommit"
        if status == "active"
        else "lastMergeCommit"
    )
    source_commit = (pull_request.get(commit_field) or {}).get("commitId", "")
    if not _COMMIT_PATTERN.fullmatch(source_commit):
        commit_kind = "source" if status == "active" else "merge"
        raise ResolutionError(
            f"PR {pull_request_id} did not resolve to a full "
            f"{commit_kind} commit"
        )
    return pull_request, source_commit


def _is_profile_path(path):
    return bool(
        path
        and path.startswith(f"{PROFILE_ROOT}/")
        and path.endswith(".json")
    )


def _change_types(value):
    return {
        change_type.strip().lower()
        for change_type in str(value or "").split(",")
        if change_type.strip()
    }


def _changed_paths(
    collection_uri, project_id, repository_id, token, pull_request_id
):
    iterations_url = _repository_url(
        collection_uri,
        project_id,
        repository_id,
        f"pullRequests/{pull_request_id}/iterations",
    )
    iterations = _request_json(
        iterations_url, token, {"api-version": "7.1"}
    ).get("value", [])
    if not iterations:
        raise ResolutionError(f"PR {pull_request_id} has no iterations")

    iteration_id = max(int(iteration["id"]) for iteration in iterations)
    changes_url = _repository_url(
        collection_uri,
        project_id,
        repository_id,
        f"pullRequests/{pull_request_id}/iterations/{iteration_id}/changes",
    )

    paths = set()
    skip = 0
    while True:
        response = _request_json(
            changes_url,
            token,
            {
                "$compareTo": 0,
                "$skip": skip,
                "$top": 2000,
                "api-version": "7.1",
            },
        )
        entries = response.get("changeEntries", response.get("value", []))
        for entry in entries:
            change_types = _change_types(entry.get("changeType"))
            path = (entry.get("item") or {}).get("path")
            destructive_profile_path = next(
                (
                    candidate
                    for candidate in (
                        path,
                        entry.get("originalPath"),
                        entry.get("sourceServerItem"),
                    )
                    if _is_profile_path(candidate)
                ),
                None,
            )
            if "delete" in change_types:
                if destructive_profile_path:
                    raise ResolutionError(
                        "Manual KubeSonic runs cannot infer a deleted "
                        "profile: "
                        f"{destructive_profile_path}"
                    )
                continue
            if change_types.intersection(
                {"rename", "sourcerename", "targetrename"}
            ) and destructive_profile_path:
                raise ResolutionError(
                    "Manual KubeSonic runs cannot infer a renamed profile: "
                    f"{destructive_profile_path}"
                )
            if path:
                paths.add(path)

        next_skip = response.get("nextSkip")
        if not next_skip or int(next_skip) <= skip:
            break
        skip = int(next_skip)
    return sorted(paths)


def _resolve_changed_profile_path(changed_paths):
    profiles = [path for path in changed_paths if _is_profile_path(path)]
    if len(profiles) != 1:
        joined = ", ".join(profiles) if profiles else "none"
        raise ResolutionError(
            "Manual KubeSonic runs require exactly one changed "
            f"{PROFILE_ROOT}/*.json profile; found {joined}"
        )
    return profiles[0]


def _resolve_named_profile_path(profile_name):
    name = (
        profile_name[:-5]
        if profile_name.endswith(".json")
        else profile_name
    )
    if not _NAME_PATTERN.fullmatch(name):
        raise ResolutionError(
            "Profile names may contain only letters, numbers, dots, "
            "underscores, and hyphens"
        )
    path = PurePosixPath(f"{PROFILE_ROOT}/{name}.json")
    normalized = str(path)
    if (
        normalized == PROFILE_ROOT
        or not normalized.startswith(f"{PROFILE_ROOT}/")
        or not normalized.endswith(".json")
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise ResolutionError(
            f"Profiles must reference {PROFILE_ROOT}/*.json"
        )
    return normalized


def _fetch_profile(
    collection_uri,
    project_id,
    repository_id,
    token,
    source_commit,
    profile_path,
):
    items_url = _repository_url(
        collection_uri, project_id, repository_id, "items"
    )
    response = _request_json(
        items_url,
        token,
        {
            "path": profile_path,
            "versionDescriptor.version": source_commit,
            "versionDescriptor.versionType": "commit",
            "includeContent": "true",
            "api-version": "7.1",
        },
    )
    content = response.get("content")
    if not isinstance(content, str):
        message = (
            f"Profile {profile_path} has no readable content "
            f"at {source_commit}"
        )
        raise ResolutionError(message)
    try:
        return json.loads(content)
    except json.JSONDecodeError as error:
        raise ResolutionError(
            f"Profile {profile_path} is not valid JSON: {error}"
        ) from error


def _validate_selector(selector):
    if not isinstance(selector, str) or "\\" in selector or "//" in selector:
        raise ResolutionError(f"Unsupported test selector: {selector}")

    selector_parts = selector.split("::")
    path = PurePosixPath(selector_parts[0])
    if (
        path.is_absolute()
        or not path.parts
        or path.parts[0] != "k8s_container"
        or any(part in ("", ".", "..") for part in path.parts)
        or not path.name.startswith("test_")
        or path.suffix != ".py"
    ):
        raise ResolutionError(
            "Selectors must reference test_*.py files under k8s_container/: "
            f"{selector}"
        )
    for part in path.parts:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", part):
            raise ResolutionError(f"Unsupported selector path: {selector}")
    for node in selector_parts[1:]:
        if not _NODE_PATTERN.fullmatch(node):
            raise ResolutionError(
                f"Unsupported pytest node selector: {selector}"
            )


def _validate_string_list(name, value, pattern=None):
    if not isinstance(value, list) or not value:
        raise ResolutionError(f"{name} must be a non-empty list")
    result = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise ResolutionError(f"{name} entries must be non-empty strings")
        if pattern and not pattern.fullmatch(item):
            raise ResolutionError(f"Unsupported {name} entry: {item}")
        result.append(item)
    return result


def _validate_profile(profile):
    if not isinstance(profile, dict):
        raise ResolutionError("The KubeSonic profile must be a JSON object")

    allowed_keys = {"version", "description", "selectors"}
    unknown_keys = sorted(set(profile) - allowed_keys)
    if unknown_keys:
        raise ResolutionError(
            f"Unsupported profile fields: {', '.join(unknown_keys)}"
        )
    if profile.get("version") != 2:
        raise ResolutionError("Profile version must be 2")
    description = profile.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ResolutionError(
            "Profile description must be a non-empty string"
        )

    selectors = _validate_string_list("selectors", profile.get("selectors"))
    for selector in selectors:
        _validate_selector(selector)

    return {"selectors": selectors}


def _get_elastictest_token(client_id, managed_identity_id):
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            subprocess.run(
                [
                    "az",
                    "login",
                    "--identity",
                    "--client-id",
                    managed_identity_id,
                    "--output",
                    "none",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            token = subprocess.check_output(
                [
                    "az",
                    "account",
                    "get-access-token",
                    "--resource",
                    client_id,
                    "--query",
                    "accessToken",
                    "--output",
                    "tsv",
                ],
                text=True,
            ).strip()
            if not token:
                raise ResolutionError(
                    "Managed identity returned an empty Elastictest token"
                )
            return token
        except (ResolutionError, subprocess.CalledProcessError):
            if attempt == MAX_ATTEMPTS:
                raise
            time.sleep(2 ** (attempt - 1))


def _query_testbeds(token):
    testbeds = []
    page = 1
    page_size = 2000
    while True:
        response = _request_json(
            MANAGEMENT_URL,
            token,
            {
                "keyword": "",
                "testbed_type": "PHYSICAL",
                "page": page,
                "page_size": page_size,
            },
        )
        if response.get("failed") or response.get("success") is False:
            detail = response.get("errmsg", "unknown error")
            raise ResolutionError(
                f"Elastictest testbed query failed: {detail}"
            )

        current_page = response.get("data")
        if not isinstance(current_page, list):
            raise ResolutionError("Elastictest returned no testbed list")
        testbeds.extend(current_page)

        total = response.get("total")
        if not current_page or (
            isinstance(total, int) and len(testbeds) >= total
        ):
            break
        if len(current_page) < page_size:
            break
        page += 1
    return testbeds


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() == "true"
    return bool(value)


def _testbed_duts(testbed):
    duts = testbed.get("dut", testbed.get("duts", []))
    if isinstance(duts, list):
        return duts
    if isinstance(duts, dict):
        return list(duts.values())
    return []


def _ineligible_reasons(testbed):
    reasons = []
    name = str(testbed.get("name", ""))
    topology = str(testbed.get("topo", ""))
    status = str(testbed.get("status", ""))
    comment = json.dumps(testbed.get("comment", ""), ensure_ascii=True).lower()

    if not _NAME_PATTERN.fullmatch(name):
        reasons.append("name contains unsupported characters")
    if not _TOPOLOGY_PATTERN.fullmatch(topology):
        reasons.append("topology contains unsupported characters")
    if testbed.get("testbed_type", "PHYSICAL") != "PHYSICAL":
        reasons.append("not physical")
    if status != "READY":
        reasons.append(f"status is {status or 'unknown'}")
    if testbed.get("locked_by"):
        reasons.append(f"locked by {testbed.get('locked_by')}")
    if _as_bool(testbed.get("nightly_test")):
        reasons.append("reserved for nightly")
    if any(tag in comment for tag in DISALLOWED_COMMENT_TAGS):
        reasons.append("excluded by comment tag")
    return reasons


def _select_exact_testbed(testbeds, requested_testbed):
    if not _NAME_PATTERN.fullmatch(requested_testbed):
        raise ResolutionError(
            "TESTBED must be an exact name containing only letters, "
            "numbers, dots, underscores, and hyphens"
        )

    by_name = {
        str(testbed.get("name")): testbed
        for testbed in testbeds
        if testbed.get("name")
    }
    testbed = by_name.get(requested_testbed)
    if not testbed:
        suggestions = difflib.get_close_matches(
            requested_testbed, sorted(by_name), n=5
        )
        suffix = (
            f"; closest matches: {', '.join(suggestions)}"
            if suggestions
            else ""
        )
        raise ResolutionError(
            f"Unknown physical testbed {requested_testbed}{suffix}"
        )
    reasons = _ineligible_reasons(testbed)
    if reasons:
        detail = ", ".join(reasons)
        raise ResolutionError(
            f"Testbed {requested_testbed} is not eligible: {detail}"
        )
    return testbed


def _set_variable(name, value):
    text = str(value)
    if "\r" in text or "\n" in text:
        raise ResolutionError(f"Resolved variable {name} contains a newline")
    print(f"##vso[task.setvariable variable={name}]{text}")


def _write_summary(
    pull_request_id,
    source_commit,
    profile_path,
    selected_testbed,
    resolved_profile,
):
    summary_path = Path.cwd() / "kubesonic-request-summary.md"
    selectors = "<br>".join(
        f"`{selector}`" for selector in resolved_profile["selectors"]
    )
    summary_path.write_text(
        "\n".join(
            [
                "# KubeSonic manual request",
                "",
                "| Field | Resolved value |",
                "|---|---|",
                f"| Source PR | `{pull_request_id}` |",
                f"| Source commit | `{source_commit}` |",
                f"| Test profile | `{profile_path}` |",
                f"| Testbed | `{selected_testbed['name']}` |",
                f"| Topology | `{selected_testbed['topo']}` |",
                f"| Test selectors | {selectors} |",
                f"| Pytest options | `{SUITE_OPTION}` |",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(f"##vso[task.uploadsummary]{summary_path}")


def main():
    try:
        if _required("PIPELINE_REF") != "refs/heads/internal":
            raise ResolutionError(
                "Run this pipeline from refs/heads/internal; "
                "PR_ID selects test code"
            )

        pull_request_id = int(_required("PR_ID"))
        if pull_request_id <= 0:
            raise ResolutionError("PR_ID must be a positive integer")

        requested_testbed = _required("TESTBED")
        if not _NAME_PATTERN.fullmatch(requested_testbed):
            raise ResolutionError(
                "TESTBED must be an exact name containing only letters, "
                "numbers, dots, underscores, and hyphens"
            )

        azure_token = _required("AZURE_DEVOPS_TOKEN")
        collection_uri = _required("SYSTEM_COLLECTION_URI")
        project_id = _required("SYSTEM_TEAM_PROJECT_ID")
        repository_id = _required("BUILD_REPOSITORY_ID")

        _, source_commit = _resolve_pull_request(
            collection_uri,
            project_id,
            repository_id,
            azure_token,
            pull_request_id,
        )
        changed_paths = _changed_paths(
            collection_uri,
            project_id,
            repository_id,
            azure_token,
            pull_request_id,
        )
        profile_path = _resolve_changed_profile_path(changed_paths)
        profile = _fetch_profile(
            collection_uri,
            project_id,
            repository_id,
            azure_token,
            source_commit,
            profile_path,
        )
        resolved_profile = _validate_profile(profile)

        elastictest_token = _get_elastictest_token(
            _required("ELASTICTEST_MSAL_CLIENT_ID"),
            _required("SONIC_AUTOMATION_UMI"),
        )
        testbeds = _query_testbeds(elastictest_token)
        selected_testbed = _select_exact_testbed(
            testbeds,
            requested_testbed,
        )

        specific_param = json.dumps(
            [
                {
                    "name": "k8s_container",
                    "param": SUITE_OPTION,
                }
            ],
            separators=(",", ":"),
        )
        _set_variable("resolvedSourceCommit", source_commit)
        _set_variable(
            "resolvedTestScripts", ",".join(resolved_profile["selectors"])
        )
        _set_variable("resolvedSpecificParam", specific_param)
        _set_variable("resolvedTestbedName", selected_testbed["name"])
        _set_variable("resolvedTopology", selected_testbed["topo"])
        _write_summary(
            pull_request_id,
            source_commit,
            profile_path,
            selected_testbed,
            resolved_profile,
        )

        print(
            f"Resolved PR {pull_request_id} at {source_commit} to "
            f"{selected_testbed['name']} ({selected_testbed['topo']})"
        )
        return 0
    except (
        ResolutionError,
        OSError,
        subprocess.CalledProcessError,
        ValueError,
    ) as error:
        print(f"KubeSonic request resolution failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

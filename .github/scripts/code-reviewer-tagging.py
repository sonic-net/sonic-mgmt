import os
from github import Github
from github import Auth
from codeowners import CodeOwners

# Get the GITHUB_TOKEN from environment variables
github_token = os.environ.get('GITHUB_TOKEN')

if not github_token:
    print("Error: GITHUB_TOKEN not found in environment variables.")
    exit(1)

# Initialize PyGithub with the token
g = Github(auth=Auth.Token(github_token))

# Get the repository and pull request information from the GitHub Actions context
# You'll need to parse the GITHUB_EVENT_PATH for detailed PR info
# For simplicity, let's assume you know the repo and PR number
repo_name = os.environ.get('GITHUB_REPOSITORY')  # e.g., "owner/repo"
if repo_name:
    owner, repo_short_name = repo_name.split('/')
    repo = g.get_user(owner).get_repo(repo_short_name)
else:
    print("Error: GITHUB_REPOSITORY not found.")
    exit(1)

# Example: Get the current pull request (if triggered by a PR event)
# This requires parsing the event payload, which can be done with `json`
# For a direct example, let's assume a PR number is passed or determined
# from the context. In a real PR-triggered action, you'd get it from `github.event.pull_request.number`
# For demonstration, let's assume PR number 1
pull_request_number = int(os.environ.get('PR_NUMBER'))

try:
    pull_request = repo.get_pull(pull_request_number)
    print(f"Pull Request Title: {pull_request.title}")
    print(f"Pull Request URL: {pull_request.html_url}")

    owners = CodeOwners(open(".code-reviewers/CODEREVIEWERS").read())

    changed_files = [file.filename for file in pull_request.get_files()]
    owner_username_set = set()
    print("Changed files in the PR:")
    for file in changed_files:
        print(f"File: {file}")
        for owner_type, owner in owners.of(file):
            print(f"Owner {owner_type}, {owner}")
            if owner_type == 'USERNAME':
                owner_username_set.add(owner)

    # Add a comment to the PR
    if owner_username_set:
        owners_str = ", ".join(sorted(owner_username_set))
        print(f"Code contributors to review: {owners_str}")
        pull_request.create_issue_comment(f"Code contributors to review: {owners_str}")
except Exception as e:
    print(f"Error accessing PR: {e}")
    exit(1)
finally:
    os.system("git clean -ffdx")
    os.system("git reset --hard HEAD")

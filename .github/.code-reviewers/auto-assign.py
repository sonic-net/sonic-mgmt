from collections import Counter, deque
import os
from shutil import unregister_unpack_format
import yaml

from github import Auth, Github

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
GITHUB_REPOSITORY = os.environ["GITHUB_REPOSITORY"]
PR_NUMBER = int(os.environ["PR_NUMBER"])

REVIEWER_INDEX = os.environ["REVIEWER_INDEX"]
NEEDED_REVIEWER_COUNT = int(os.environ.get("NEEDED_REVIEWER_COUNT", 3))
INCLUDE_CONTRIBUTORS_TIES = os.environ.get(
    "INCLUDE_CONTRIBUTORS_TIES", "False"
).strip().lower() not in ("", "false", "f", "0", "no", "n", "off", "disabled")

# using an access token
auth = Auth.Token(GITHUB_TOKEN)

# Public Web Github
g = Github(auth=auth)

# Load the reviewer index
reviewer_index = yaml.safe_load(open(REVIEWER_INDEX))
# clean-up the trailing "/" from the paths
reviewer_index = {
    repo_path.rstrip(os.sep) if repo_path != os.sep else repo_path: contributors
    for repo_path, contributors in reviewer_index.items()
}
# Load the reop and PR information
repo = g.get_repo(GITHUB_REPOSITORY)
pr = repo.get_pull(PR_NUMBER)

# Process changed files and directories
seen_folders = set[str]()
# Perform the BFS search up to the root of the repository
# Until the sufficient number of reviewers are found
updated_folders = []
reviewer_candidates = Counter[str, int]()

# First bring each changed path to where any reviwer exists
for changed_file in pr.get_files():
    # remove the filename, add "/" to the front
    changed_path = os.path.join(os.sep, os.path.dirname(changed_file.filename))
    print(f"Processing changed path {changed_path}")
    while changed_path not in reviewer_index:
        if changed_path in seen_folders:
            break
        seen_folders.add(changed_path)
        if changed_path == os.sep:
            break
        changed_path = os.path.dirname(changed_path)
        print(f"Going up the path {changed_path}")
    else:
        # Found the lowest level contributors
        # Finished the loop without breaking
        updated_folders.append(changed_path)
print(f"Folders with contributors {updated_folders}")

# Populate the the queue with the most specific folders ad the beginning
updated_folder_queue = deque(sorted(updated_folders, reverse=True))

# Now perform the BFS until the sufficient number of reviewers is found
while updated_folder_queue and len(reviewer_candidates) < NEEDED_REVIEWER_COUNT:
    # extract all folder from the current BFS level
    for _ in range(len(updated_folder_queue)):
        changed_path = updated_folder_queue.popleft()
        reviewer_candidates += Counter(reviewer_index[changed_path])
        print(f"Path: {changed_path}, accumulated reviewers: {reviewer_candidates}")
        # do not try to go above the root
        if changed_path != os.sep:
            changed_path = os.path.dirname(changed_path)
            if changed_path not in seen_folders:
                seen_folders.add(changed_path)
                updated_folder_queue.append(changed_path)


# Select the top contributors as the reviwers
if reviewer_candidates:
    print(f"Reviewer candidates: {reviewer_candidates}")
    if INCLUDE_CONTRIBUTORS_TIES:
        reviewers_to_add = []
        # process more carefully to handle the tied contributions
        it_cand = iter(reviewer_candidates.most_common())
        reviewer, prev_change_count = next(it_cand)

        reviewers_to_add.append(reviewer)
        for reviewer, change_count in it_cand:
            if (
                len(reviewers_to_add) >= NEEDED_REVIEWER_COUNT
                and change_count < prev_change_count
            ):
                # stop when enough reviewers found and the tie is broken
                break
            reviewers_to_add.append(reviewer)
            prev_change_count = change_count

    else:
        reviewers_to_add = [
            reviewer
            for reviewer, _ in reviewer_candidates.most_common(NEEDED_REVIEWER_COUNT)
        ]

    try:
        # Request reviews
        pr.create_review_request(reviewers=reviewers_to_add)
        print(
            f"Successfully requested reviews for PR #{pr.number} from users: {reviewers_to_add}"
        )

    except Exception as e:
        print(f"An error occurred: {e}")
else:
    print("No reviewers found for this PR!")


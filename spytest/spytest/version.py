
def get_git_repo():
    try:
        import git
        return git.Repo(search_parent_directories=True)
    except Exception:
        return None

def get_git_branch(repo=None):
    try:
        repo = repo or get_git_repo()
        return repo.active_branch.name
    except Exception:
        return "UNKNOWN"

def get_git_commit(repo=None):
    try:
        repo = repo or get_git_repo()
        return repo.head.object.hexsha
    except Exception:
        return "UNKNOWN"

def get_git_ver():
    repo = get_git_repo()
    branch = get_git_branch(repo)
    commit = get_git_commit(repo)
    return "{} {}".format(branch, commit)

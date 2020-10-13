
def get_git_ver():
    try:
        import git
        repo = git.Repo(search_parent_directories=True)
        return repo.head.object.hexsha
    except:
        return "UNKNOWN"


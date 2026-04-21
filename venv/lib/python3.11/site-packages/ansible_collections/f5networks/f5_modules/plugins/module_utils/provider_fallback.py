import os


def smart_fallback(module, varnames):
    """
    Compatible with Ansible's load_provider() fallback logic.
    1. Checks Ansible task-level environment (via `environment:`)
    2. Falls back to process env (os.environ)
    """
    try:
        if module and hasattr(module._task, 'environment'):
            env = module._task.environment
            for var in varnames:
                if var in env:
                    return env[var]
    except Exception:
        pass

    for var in varnames:
        if var in os.environ:
            return os.environ[var]

    return None

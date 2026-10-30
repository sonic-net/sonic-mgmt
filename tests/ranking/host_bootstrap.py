"""Create a private agent directory without trusting pre-existing host paths."""
import json
import os
import stat
import sys


def ensure_agent_directory(base, target):
    for path in (base, target):
        if (not isinstance(path, str) or not os.path.isabs(path) or path == '/' or
                os.path.normpath(path) != path):
            raise ValueError('Agent paths must be absolute canonical directories')
    if not target.startswith(base + '/'):
        raise ValueError('Agent directory must belong to the request base')
    parts = target.strip('/').split('/')
    protected_start = len(base.strip('/').split('/')) - 1
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open('/', flags)
    try:
        for index, part in enumerate(parts):
            if index >= protected_start:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            if index >= protected_start:
                metadata = os.fstat(descriptor)
                if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                    raise ValueError('Untrusted agent directory: owner or permissions mismatch')
    finally:
        os.close(descriptor)


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if len(arguments) != 2:
            raise ValueError('Expected request base and agent directory')
        ensure_agent_directory(*arguments)
    except (OSError, ValueError) as error:
        sys.stderr.write('ranking-bootstrap: {}\n'.format(error))
        return 1
    print(json.dumps({'schema_version': 1, 'action': 'bootstrap', 'result': {}}))
    return 0


if __name__ == '__main__':
    sys.exit(main())

"""Prepare a mounted Railway data volume, then run Nexus unprivileged."""
import os
import pwd
import sys
from pathlib import Path


def main():
    if len(sys.argv) < 2:
        raise SystemExit('Missing app start command')
    # Never use a relative path for production SQLite storage.
    path = Path(os.environ.get('DATA_DIR', '/data/nexus')).resolve()
    if not path.is_absolute() or str(path) == '/':
        raise SystemExit('Invalid DATA_DIR')
    path.mkdir(parents=True, exist_ok=True)
    account = pwd.getpwnam('nexus')
    # Railway volumes are initially mounted root-owned. Only hand over the
    # dedicated application directory, not the rest of the filesystem.
    for item in (path, *path.iterdir()):
        os.chown(item, account.pw_uid, account.pw_gid)
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == '__main__':
    main()

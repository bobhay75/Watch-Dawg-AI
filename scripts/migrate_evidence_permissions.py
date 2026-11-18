#!/usr/bin/env python3
"""POSIX-only local evidence permission migration. Dry run unless --apply is set.

Stop collectors/readers first. Never reads contents, deletes, follows links or uses
network access. Preflight failures change nothing; OS failures during application
may leave a safely tightened partial migration, which can be rerun.
"""
import argparse
import os
from pathlib import Path
import stat


def migrate(root, apply=False, max_entries=512):
    if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW'):
        raise ValueError('Migration requires POSIX no-follow descriptor support')
    if '..' in Path(root).parts:
        raise ValueError('Parent traversal is not allowed in the evidence root')
    if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
        raise ValueError('Entry limit must be a positive integer')
    parts = Path(os.path.abspath(root)).parts
    if len(parts) <= 2:
        raise ValueError('Select a dedicated evidence subtree')
    handles = []
    entries = []
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        parent = os.open('/', directory_flags)
        handles.append(parent)
        for part in parts[1:]:
            parent = os.open(part, directory_flags, dir_fd=parent)
            handles.append(parent)
        root_stat = os.fstat(parent)
        device = root_stat.st_dev

        def inspect(fd, before):
            after = os.fstat(fd)
            if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError('Tree changed during preflight')
            if after.st_uid != os.getuid() or after.st_dev != device:
                raise ValueError('Foreign owner or filesystem boundary')
            if stat.S_ISREG(after.st_mode) and after.st_nlink != 1:
                raise ValueError('Hard-linked evidence is unsafe to chmod')
            target = 0o700 if stat.S_ISDIR(after.st_mode) else 0o600
            entries.append((fd, target, after))
            if len(entries) > max_entries:
                raise ValueError('Preflight entry limit exceeded; select a smaller subtree')

        inspect(parent, root_stat)
        queue = [parent]
        while queue:
            directory = queue.pop()
            for name in os.listdir(directory):
                before = os.stat(name, dir_fd=directory, follow_symlinks=False)
                is_dir = stat.S_ISDIR(before.st_mode)
                if not is_dir and not stat.S_ISREG(before.st_mode):
                    raise ValueError('Links and special files require manual review')
                flags = directory_flags if is_dir else os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                fd = os.open(name, flags, dir_fd=directory)
                handles.append(fd)
                inspect(fd, before)
                if is_dir:
                    queue.append(fd)
        def assert_stable(fd, before):
            after = os.fstat(fd)
            if (after.st_uid, after.st_nlink, after.st_mode, after.st_mtime_ns, after.st_ctime_ns) != (
                    before.st_uid, before.st_nlink, before.st_mode, before.st_mtime_ns, before.st_ctime_ns):
                raise ValueError('Tree changed; stop writers before migration')

        # Recheck the full preflight, then recheck each object immediately before chmod.
        for fd, _, before in entries:
            assert_stable(fd, before)
        changes = sum(stat.S_IMODE(info.st_mode) != mode for _, mode, info in entries)
        if apply:
            # Close directory access first; descriptors keep descendants accessible.
            for fd, mode, before in entries:
                assert_stable(fd, before)
                os.fchmod(fd, mode)
        return {'entries': len(entries), 'permission_changes': changes, 'applied': apply}
    finally:
        for fd in reversed(handles):
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, help='Existing dedicated evidence directory')
    parser.add_argument('--apply', action='store_true', help='Apply 0700 directories / 0600 files')
    args = parser.parse_args()
    try:
        result = migrate(args.root, args.apply)
    except (OSError, ValueError):
        # Do not echo paths that might identify private sites.
        parser.exit(1, 'Migration refused or interrupted; inspect locally with writers stopped. No files deleted or uploaded.\n')
    print(result)


if __name__ == '__main__':
    main()

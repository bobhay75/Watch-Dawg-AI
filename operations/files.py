"""Private local files, bounded reads and canonical integrity
representations.
"""

import hashlib
import json
import os
from pathlib import Path
import stat


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_private(path, limit=1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise ValueError("Unsafe private file")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Private file exceeds limit")
    return data


def private_directory(path, create=False):
    path = Path(path)
    if create:
        path.mkdir(mode=0o700)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        os.close(fd)
        raise ValueError("Private owned directory required")
    return fd


def write_new(path, data):
    path = Path(path)
    directory = private_directory(path.parent)
    try:
        fd = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(directory)
    finally:
        os.close(directory)

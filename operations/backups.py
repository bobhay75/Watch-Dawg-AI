"""Authenticated encrypted offline archives. No upload, pruning or in-place
restore.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
import zipfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .files import (
    canonical,
    digest,
    read_private,
    private_directory,
    write_new,
)

MAGIC = b"WATCHDAWG-BACKUP-1\n"
MANIFEST = "_watchdawg_manifest.json"
MAX_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024


def valid_name(name):
    p = PurePosixPath(name)
    return (
        bool(name)
        and not p.is_absolute()
        and "\\" not in name
        and all(part not in {"", ".", ".."} for part in name.split("/"))
    )


def key_bytes(path):
    key = read_private(path, 32)
    if len(key) != 32:
        raise ValueError("A private 256-bit encryption key is required")
    return key


def _raise_walk_error(error):
    raise error


def backup(source, key_file, destination, maximum=MAX_BYTES):
    source, destination = Path(source), Path(destination)
    if (
        source.is_symlink()
        or not source.is_dir()
        or destination.resolve().is_relative_to(source.resolve())
        or Path(key_file).resolve().is_relative_to(source.resolve())
    ):
        raise ValueError("Dedicated source and external key required")
    directory = private_directory(destination.parent)
    os.close(directory)
    if os.path.lexists(destination) or os.path.lexists(
        str(destination) + ".receipt.json"
    ):
        raise FileExistsError("Backup destination exists")
    key = key_bytes(key_file)
    with tempfile.TemporaryDirectory(
        prefix=".backup-", dir=destination.parent
    ) as temp:
        archive = Path(temp) / "private.zip"
        rows, total = [], 0
        with zipfile.ZipFile(
            archive, "w", compression=zipfile.ZIP_STORED
        ) as zipped:
            for root, dirs, files in os.walk(
                source, onerror=_raise_walk_error, followlinks=False
            ):
                if any((Path(root) / name).is_symlink() for name in dirs):
                    raise ValueError(
                        "Linked directories are not evidence snapshots"
                    )
                info = os.stat(root, follow_symlinks=False)
                if info.st_uid != os.getuid() or info.st_mode & 0o022:
                    raise ValueError(
                        "Evidence directories must be owned and not wri"
                        "table by others"
                    )
                for name in sorted(files):
                    path = Path(root) / name
                    relative = path.relative_to(source).as_posix()
                    if not valid_name(relative) or relative == MANIFEST:
                        raise ValueError("Invalid archive member")
                    if len(rows) >= 4096 or len(relative) > 1024:
                        raise ValueError("Snapshot member limit exceeded")
                    fd = os.open(
                        path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                    )
                    with os.fdopen(fd, "rb") as stream:
                        before = os.fstat(stream.fileno())
                        if (
                            before.st_uid != os.getuid()
                            or not stat.S_ISREG(before.st_mode)
                            or before.st_nlink != 1
                        ):
                            raise ValueError(
                                "Only independent regular evidence file"
                                "s are accepted"
                            )
                        total += before.st_size
                        if total > maximum:
                            raise ValueError("Evidence snapshot exceeds limit")
                        # Every member is bounded; large production snapshots
                        # need streaming tooling.
                        raw = stream.read(maximum + 1)
                        after = os.fstat(stream.fileno())
                    if len(raw) != before.st_size or (
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                    ) != (after.st_mtime_ns, after.st_ctime_ns):
                        raise ValueError(
                            "Writers must be stopped before backup"
                        )
                    zipped.writestr(relative, raw)
                    rows.append(
                        {
                            "path": relative,
                            "bytes": len(raw),
                            "sha256": digest(raw),
                        }
                    )
            manifest = canonical(
                {
                    "version": 1,
                    "files": rows,
                    "public_release_approved": False,
                }
            )
            if len(manifest) > MAX_MANIFEST_BYTES:
                raise ValueError("Snapshot manifest exceeds restore limit")
            zipped.writestr(MANIFEST, manifest)
        nonce = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(MAGIC)
        encrypted = Path(temp) / "encrypted"
        with archive.open("rb") as inp, encrypted.open("xb") as out:
            os.chmod(encrypted, 0o600)
            out.write(MAGIC + nonce)
            while chunk := inp.read(1024 * 1024):
                out.write(encryptor.update(chunk))
            out.write(encryptor.finalize() + encryptor.tag)
            out.flush()
            os.fsync(out.fileno())
        # Hard-link publication is exclusive and atomic, never replaces a
        # backup.
        os.link(encrypted, destination)
        receipt = {
            "format": 1,
            "ciphertext_sha256": digest(destination.read_bytes()),
            "files": len(rows),
            "bytes": total,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "public_release_approved": False,
        }
        write_new(str(destination) + ".receipt.json", canonical(receipt))
    return receipt


def restore(archive, key_file, destination, receipt, maximum=MAX_BYTES):
    archive, destination = Path(archive), Path(destination)
    directory = private_directory(destination.parent)
    os.close(directory)
    if os.path.lexists(destination):
        raise FileExistsError("Restore only to a new isolated destination")
    raw_receipt = json.loads(read_private(receipt))
    encrypted = read_private(archive, maximum + 32 * 1024 * 1024)
    if digest(encrypted) != raw_receipt.get(
        "ciphertext_sha256"
    ) or not encrypted.startswith(MAGIC):
        raise ValueError("Backup receipt or header mismatch")
    start = len(MAGIC)
    end = start + 12
    nonce, ciphertext, tag = (
        encrypted[start:end],
        encrypted[end:-16],
        encrypted[-16:],
    )
    decryptor = Cipher(
        algorithms.AES(key_bytes(key_file)), modes.GCM(nonce, tag)
    ).decryptor()
    decryptor.authenticate_additional_data(MAGIC)
    with tempfile.TemporaryDirectory(
        prefix=".restore-", dir=destination.parent
    ) as temp:
        plain = Path(temp) / "private.zip"
        with plain.open("xb") as stream:
            os.chmod(plain, 0o600)
            stream.write(decryptor.update(ciphertext))
            stream.write(
                decryptor.finalize()
            )  # Authenticate before any evidence extraction.
        stage = Path(temp) / "verified"
        stage.mkdir(mode=0o700)
        with zipfile.ZipFile(plain) as zipped:
            members = zipped.infolist()
            names = [m.filename for m in members]
            if (
                len(names) > 4097
                or len(names) != len(set(names))
                or names.count(MANIFEST) != 1
                or any(not valid_name(n) or len(n) > 1024 for n in names)
            ):
                raise ValueError("Unsafe archive paths or duplicate members")
            if (
                zipped.getinfo(MANIFEST).file_size > MAX_MANIFEST_BYTES
                or sum(m.file_size for m in members if m.filename != MANIFEST)
                > maximum
            ):
                raise ValueError("Archive expansion exceeds limit")
            manifest = json.loads(zipped.read(MANIFEST))
            rows = manifest["files"]
            if (
                manifest.get("public_release_approved") is not False
                or manifest.get("version") != 1
            ):
                raise ValueError("Invalid evidence manifest")
            if (
                set(names) != {MANIFEST, *(row["path"] for row in rows)}
                or len(rows) != len(names) - 1
            ):
                raise ValueError("Manifest does not bind every member")
            for row in rows:
                info = zipped.getinfo(row["path"])
                if (
                    stat.S_ISLNK(info.external_attr >> 16)
                    or info.file_size != row["bytes"]
                ):
                    raise ValueError("Invalid member type or size")
                data = zipped.read(info)
                if digest(data) != row["sha256"]:
                    raise ValueError("Evidence integrity mismatch")
                target = stage / row["path"]
                parent = stage
                for component in Path(row["path"]).parent.parts:
                    parent = parent / component
                    parent.mkdir(mode=0o700, exist_ok=True)
                write_new(target, data)
        os.rename(stage, destination)
        fd = private_directory(destination.parent)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return {"restored_files": len(rows), "public_release_approved": False}

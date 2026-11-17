"""Durable private audit journal with bounded storage and minimum retention."""

from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time
import threading
import uuid


class AuditUnavailable(RuntimeError):
    pass


def validate(event):
    common = {"event", "timestamp", "request_id", "principal_ref"}
    kinds = {
        "backend_request": {"route", "status"},
        "backend_stream": {"outcome"},
        "backend_admission": {"route", "decision"},
    }
    kind = event.get("event")
    if kind not in kinds or set(event) != common | kinds[kind]:
        raise ValueError("Unknown audit schema")
    if not re.fullmatch("[0-9a-f]{32}", event["request_id"]):
        raise ValueError("Invalid generated request reference")
    if event["principal_ref"] != "anonymous" and not re.fullmatch(
        "[0-9a-f]{64}", event["principal_ref"]
    ):
        raise ValueError("Invalid pseudonymous principal")
    stamp = datetime.fromisoformat(event["timestamp"])
    if not stamp.tzinfo:
        raise ValueError("Audit timestamp requires timezone")
    if "route" in event and event["route"] not in {"health", "audit", "other"}:
        raise ValueError("Private paths are forbidden in logs")
    if kind == "backend_request" and (
        type(event["status"]) is not int or not 100 <= event["status"] <= 599
    ):
        raise ValueError("Invalid status")
    if kind == "backend_stream" and event["outcome"] not in {
        "completed",
        "failed",
        "cancelled",
    }:
        raise ValueError("Invalid outcome")
    if kind == "backend_admission" and event["decision"] != "authorized":
        raise ValueError("Invalid admission")


class AuditJournal:
    """All writers share flock. Refuses nonempty foreign folders.

    Only expired segments are pruned. Capacity failures preserve retention.
    """

    def __init__(
        self,
        directory,
        segment_bytes=1024 * 1024,
        max_segments=8,
        retention_days=7,
        min_free_bytes=10 * 1024 * 1024,
    ):
        if (
            not 1024 <= segment_bytes <= 64 * 1024 * 1024
            or not 2 <= max_segments <= 128
            or not 1 <= retention_days <= 365
        ):
            raise AuditUnavailable("Invalid audit storage policy")
        self.thread_lock = threading.RLock()
        self.path = Path(directory)
        self.segment_bytes, self.max_segments = segment_bytes, max_segments
        self.retention = retention_days * 86400
        self.min_free = min_free_bytes
        self.fd = os.open(
            directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            self._owned(os.fstat(self.fd), directory=True)
            initial = set(os.listdir(self.fd))
            if ".watchdawg-audit-v1" not in initial and initial - {
                ".audit.lock"
            }:
                raise AuditUnavailable("Audit directory is not dedicated")
            self.lock = os.open(
                ".audit.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
                dir_fd=self.fd,
            )
            self._owned(os.fstat(self.lock))
            with self:
                names = set(os.listdir(self.fd))
                if ".watchdawg-audit-v1" not in names:
                    if names - {".audit.lock"}:
                        raise AuditUnavailable(
                            "Audit directory is not dedicated"
                        )
                    marker = os.open(
                        ".watchdawg-audit-v1",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=self.fd,
                    )
                    with os.fdopen(marker, "wb") as stream:
                        stream.write(b"watchdawg-audit-v1\n")
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.fsync(self.fd)
                self._segments()
        except BaseException:
            if hasattr(self, "lock"):
                os.close(self.lock)
            os.close(self.fd)
            raise

    @staticmethod
    def _owned(info, directory=False):
        regular = (
            stat.S_ISDIR(info.st_mode)
            if directory
            else stat.S_ISREG(info.st_mode)
        )
        if (
            not regular
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or (not directory and info.st_nlink != 1)
        ):
            raise AuditUnavailable("Unsafe audit storage")

    def __enter__(self):
        self.thread_lock.acquire()
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX)
        except BaseException:
            self.thread_lock.release()
            raise
        return self

    def __exit__(self, *args):
        fcntl.flock(self.lock, fcntl.LOCK_UN)
        self.thread_lock.release()

    def _segments(self):
        segments = []
        for name in os.listdir(self.fd):
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            self._owned(info)
            if name in {".audit.lock", ".watchdawg-audit-v1"}:
                continue
            if not re.fullmatch(r"audit-[0-9]{20}-[0-9a-f]{32}\.jsonl", name):
                raise AuditUnavailable("Foreign file in audit directory")
            if info.st_size > self.segment_bytes:
                raise AuditUnavailable("Audit segment exceeds policy")
            segments.append((name, info))
        return sorted(segments)

    def write(self, event):
        try:
            validate(event)
            line = (
                json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode()
            if len(line) > self.segment_bytes:
                raise ValueError("Audit event exceeds limit")
            with self:
                if shutil.disk_usage(self.path).free < self.min_free:
                    raise AuditUnavailable("Audit storage reserve exhausted")
                segments = self._segments()
                kept = []
                now = time.time()
                for name, info in segments:
                    if now - info.st_mtime >= self.retention:
                        os.unlink(name, dir_fd=self.fd)
                    else:
                        kept.append((name, info))
                os.fsync(self.fd)
                if len(kept) > self.max_segments:
                    raise AuditUnavailable(
                        "Audit segment count exceeds policy"
                    )
                today = datetime.now(timezone.utc).strftime("%Y%m%d")
                if (
                    kept
                    and kept[-1][0][6:14] == today
                    and kept[-1][1].st_size + len(line) <= self.segment_bytes
                ):
                    name = kept[-1][0]
                    check = os.open(
                        name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd
                    )
                    with os.fdopen(check, "rb") as stream:
                        if kept[-1][1].st_size:
                            stream.seek(-1, os.SEEK_END)
                            if stream.read(1) != b"\n":
                                raise AuditUnavailable(
                                    "Incomplete audit tail requires review"
                                )
                    flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
                else:
                    if len(kept) >= self.max_segments:
                        raise AuditUnavailable(
                            "Minimum audit retention would be violated"
                        )
                    name = (
                        "audit-"
                        + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
                        + "-"
                        + uuid.uuid4().hex
                        + ".jsonl"
                    )
                    flags = (
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    )
                fd = os.open(name, flags, 0o600, dir_fd=self.fd)
                with os.fdopen(fd, "ab") as stream:
                    self._owned(os.fstat(stream.fileno()))
                    stream.write(line)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(self.fd)
        except AuditUnavailable:
            raise
        except Exception:
            raise AuditUnavailable("Durable audit unavailable") from None

    def close(self):
        os.close(self.lock)
        os.close(self.fd)

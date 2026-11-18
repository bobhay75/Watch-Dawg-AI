"""Reviewed role documents; applying requires a caller-supplied admin
connection.
"""

import re


def roles(database):
    if not re.fullmatch("[A-Za-z0-9_-]{1,64}", database):
        raise ValueError("Invalid dedicated database name")
    return [
        {
            "role": "watchdawg_app",
            "privileges": [
                {
                    "resource": {
                        "db": database,
                        "collection": "ai_audit_messages",
                    },
                    "actions": ["insert"],
                },
                *[
                    {
                        "resource": {"db": database, "collection": name},
                        "actions": ["find", "insert", "update", "createIndex"],
                    }
                    for name in ("security_windows", "security_leases")
                ],
            ],
            "roles": [],
        },
        {
            "role": "watchdawg_backup",
            "privileges": [
                {
                    "resource": {
                        "db": database,
                        "collection": "ai_audit_messages",
                    },
                    "actions": ["find"],
                },
            ],
            "roles": [],
        },
    ]


def provision(database, passwords):
    """No default URI, environment lookup, admin user or password
    persistence.
    """
    for user in ("watchdawg_app", "watchdawg_backup"):
        if (
            not isinstance(passwords.get(user), str)
            or len(passwords[user]) < 32
        ):
            raise ValueError("High-entropy credentials required")
    for role in roles(database.name):
        database.command("createRole", **role)
    for user, role in [
        ("watchdawg_app", "watchdawg_app"),
        ("watchdawg_backup", "watchdawg_backup"),
    ]:
        if not isinstance(passwords[user], str) or len(passwords[user]) < 32:
            raise ValueError("High-entropy credentials required")
        database.command(
            "createUser",
            user,
            pwd=passwords[user],
            roles=[{"role": role, "db": database.name}],
        )

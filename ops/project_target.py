"""One Owner-scoped project identity for all existing and future managed repositories.

This is a syntactic gate, NEVER a grant of GitHub access. The authenticated
Owner Issue and a repository-scoped publisher credential must be verified
independently before running a model or publishing a patch.
"""
from __future__ import annotations

import re

OWNER = "martaxi-boss"
_REPOSITORY = re.compile(r"martaxi-boss/[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z", re.ASCII)
PREFIX = "TARGET_REPOSITORY="


class TargetRefused(ValueError):
    """Untrusted, malformed or out-of-owner project selector."""


def is_managed_target(value: object) -> bool:
    if type(value) is not str or _REPOSITORY.fullmatch(value) is None:
        return False
    name = value.split("/", 1)[1]
    return not (name.endswith(".") or name.endswith(".git")
                or ".." in name or name.startswith("-"))


def from_owner_order(body: object) -> str:
    """Read ONLY the exact first line; other text never changes the target."""
    if type(body) is not str or not body:
        raise TargetRefused("Missing Owner target")
    first = body.split("\n", 1)[0]
    if not first.startswith(PREFIX):
        raise TargetRefused("Missing repository selector")
    target = first[len(PREFIX):]
    if not is_managed_target(target):
        raise TargetRefused("Untrusted repository selector")
    return target

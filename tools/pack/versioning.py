"""Strict SemVer precedence for Atlas runtime compatibility and rollback guards."""
from __future__ import annotations

import re
from dataclasses import dataclass

SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


class VersionError(ValueError):
    """Raised when a version is not strict SemVer or violates precedence rules."""


@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str) -> "SemVer":
        if not isinstance(value, str):
            raise VersionError("version must be a string")
        match = SEMVER_RE.fullmatch(value)
        if not match:
            raise VersionError(f"invalid strict SemVer: {value!r}")
        pre = tuple(match.group(4).split(".")) if match.group(4) else ()
        for token in pre:
            if token.isdigit() and len(token) > 1 and token.startswith("0"):
                raise VersionError(f"numeric prerelease identifier has leading zero: {value!r}")
        return cls(int(match.group(1)), int(match.group(2)), int(match.group(3)), pre)

    def _core(self) -> tuple[int, int, int]:
        return self.major, self.minor, self.patch

    def compare(self, other: "SemVer") -> int:
        if self._core() != other._core():
            return -1 if self._core() < other._core() else 1
        if self.prerelease == other.prerelease:
            return 0
        if not self.prerelease:
            return 1
        if not other.prerelease:
            return -1

        for left, right in zip(self.prerelease, other.prerelease):
            if left == right:
                continue
            left_num = left.isdigit()
            right_num = right.isdigit()
            if left_num and right_num:
                return -1 if int(left) < int(right) else 1
            if left_num != right_num:
                return -1 if left_num else 1
            return -1 if left < right else 1
        return -1 if len(self.prerelease) < len(other.prerelease) else 1


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0 or 1 according to SemVer precedence."""
    return SemVer.parse(left).compare(SemVer.parse(right))


def require_runtime_compatible(minimum_runtime: str, current_runtime: str) -> None:
    if compare_versions(current_runtime, minimum_runtime) < 0:
        raise VersionError(
            f"runtime {current_runtime} is below pack minimum {minimum_runtime}"
        )

"""Segregation of duties: pairs of permissions one person must not hold together."""

from __future__ import annotations

from dataclasses import dataclass

from .authz import permissions_for


@dataclass(frozen=True)
class SodRule:
    rule_id: str
    a: str
    b: str
    why: str


RULES = (
    SodRule("SOD-1", "vendor:create", "payment:approve", "could invent a restaurant and pay it"),
    SodRule("SOD-2", "refunds:issue", "refunds:read_archive", "could issue and then hide refund evidence"),
    SodRule("SOD-3", "directory:admin", "payment:approve", "could grant themselves approval rights"),
)


def conflicts(roles: set[str]) -> list[SodRule]:
    perms = permissions_for(roles)
    return [r for r in RULES if r.a in perms and r.b in perms]


def would_conflict(current: set[str], new_role: str) -> list[SodRule]:
    before = {r.rule_id for r in conflicts(current)}
    return [r for r in conflicts(current | {new_role}) if r.rule_id not in before]

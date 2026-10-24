"""The directory: user objects and groups. Group membership is how roles are assigned."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DirUser:
    user_id: str
    employee_id: str
    username: str
    department: str
    country: str
    enabled: bool = True
    kind: str = "workforce"  # workforce | guest | break_glass


@dataclass
class Directory:
    users: dict[str, DirUser] = field(default_factory=dict)
    groups: dict[str, set[str]] = field(default_factory=dict)

    def upsert(self, u: DirUser) -> DirUser:
        self.users[u.user_id] = u
        return u

    def by_employee(self, employee_id: str) -> DirUser | None:
        return next((u for u in self.users.values() if u.employee_id == employee_id), None)

    def add_to_group(self, group: str, user_id: str) -> None:
        self.groups.setdefault(group, set()).add(user_id)

    def remove_from_group(self, group: str, user_id: str) -> None:
        self.groups.get(group, set()).discard(user_id)

    def groups_of(self, user_id: str) -> set[str]:
        return {g for g, members in self.groups.items() if user_id in members}

    def disable(self, user_id: str) -> None:
        self.users[user_id].enabled = False

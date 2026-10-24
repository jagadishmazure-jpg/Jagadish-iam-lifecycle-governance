"""HR is the source of truth. Identity changes start here as events, never in the apps."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Worker:
    employee_id: str
    display_name: str
    work_email: str
    department: str
    title: str
    manager_id: str | None
    country: str
    status: str = "active"  # active | terminated
    worker_type: str = "employee"  # employee | contractor


@dataclass(frozen=True)
class HrEvent:
    kind: str  # hire | transfer | terminate
    employee_id: str
    new_department: str | None = None
    new_title: str | None = None


@dataclass
class HrSystem:
    workers: dict[str, Worker] = field(default_factory=dict)
    outbox: list[HrEvent] = field(default_factory=list)

    def hire(self, w: Worker) -> HrEvent:
        if w.employee_id in self.workers:
            raise ValueError(f"employee id {w.employee_id} already exists")
        self.workers[w.employee_id] = w
        ev = HrEvent("hire", w.employee_id)
        self.outbox.append(ev)
        return ev

    def transfer(self, employee_id: str, department: str, title: str) -> HrEvent:
        w = self.workers[employee_id]
        if w.status != "active":
            raise ValueError("cannot transfer a terminated worker")
        w.department, w.title = department, title
        ev = HrEvent("transfer", employee_id, department, title)
        self.outbox.append(ev)
        return ev

    def terminate(self, employee_id: str) -> HrEvent:
        w = self.workers[employee_id]
        w.status = "terminated"
        ev = HrEvent("terminate", employee_id)
        self.outbox.append(ev)
        return ev

    def drain(self) -> list[HrEvent]:
        out, self.outbox = self.outbox, []
        return out

    def is_active(self, employee_id: str) -> bool:
        w = self.workers.get(employee_id)
        return bool(w and w.status == "active")

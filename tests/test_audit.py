from dataclasses import replace

from iamlc.audit import AuditLog
from iamlc.clock import Clock


def make(n=5):
    log = AuditLog(Clock())
    for i in range(n):
        log.record("sys", "act", f"t{i}")
    return log


def test_chain_valid():
    assert make().verify_chain()


def test_tamper_detected():
    log = make()
    log.events[2] = replace(log.events[2], outcome="denied")
    assert not log.verify_chain()


def test_deletion_detected():
    log = make()
    del log.events[1]
    assert not log.verify_chain()


def test_find_filters():
    log = make()
    log.record("sys", "other", "t9", "denied")
    assert len(log.find(action="act")) == 5
    assert len(log.find(outcome="denied")) == 1
    assert len(log.find(target="t9")) == 1


def test_empty_chain_valid():
    assert AuditLog(Clock()).verify_chain()

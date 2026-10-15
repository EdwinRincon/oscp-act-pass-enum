from types import SimpleNamespace

import pytest

from osint import registry
from osint.models import ModuleResult, ScanError, Status
from osint.registry import ModuleSpec, validate_specs
from osint.runner import INTERRUPTED, order_by_dependencies, run_all
from osint.service import prepare


def fake_spec(id, run, requires=(), confidence="High"):
    module = SimpleNamespace(run=run)
    return SimpleNamespace(
        id=id, title=f"T-{id}", phase="passive", source="src", kind="finding",
        confidence=confidence, requires=requires, factory=lambda ctx: module,
    )


def ok_run(domain):
    return ModuleResult("x", "y", Status.OK)


# --- ordering -------------------------------------------------------------

def test_dependencies_come_first():
    a = fake_spec("a", ok_run, requires=("b",))
    b = fake_spec("b", ok_run)
    assert [s.id for s in order_by_dependencies([a, b])] == ["b", "a"]


def test_order_is_stable_without_dependencies():
    specs = [fake_spec(i, ok_run) for i in "abc"]
    assert [s.id for s in order_by_dependencies(specs)] == ["a", "b", "c"]


def test_missing_dependency_is_ignored():
    a = fake_spec("a", ok_run, requires=("absent",))
    assert [s.id for s in order_by_dependencies([a])] == ["a"]


def test_cycle_raises_scan_error():
    a = fake_spec("a", ok_run, requires=("b",))
    b = fake_spec("b", ok_run, requires=("a",))
    with pytest.raises(ScanError):
        order_by_dependencies([a, b])


# --- run_all --------------------------------------------------------------

def test_success_is_stamped_with_spec_metadata():
    results = run_all([fake_spec("a", ok_run)], client=None, domain="example.com")
    res = results[0]
    assert (res.id, res.name, res.source, res.kind) == ("a", "T-a", "src", "finding")
    assert res.confidence == "High" and res.status == "ok"
    assert res.started_at and res.elapsed >= 0


def test_failure_is_isolated_and_confidence_is_na():
    def boom(domain):
        raise RuntimeError("nope")

    results = run_all([fake_spec("a", boom), fake_spec("b", ok_run)], None, "example.com")
    assert [r.status for r in results] == ["failed", "ok"]
    assert results[0].error == "RuntimeError: nope"
    assert results[0].confidence == "n/a"


def test_error_message_is_truncated():
    def boom(domain):
        raise RuntimeError("x" * 1000)

    res = run_all([fake_spec("a", boom)], None, "example.com")[0]
    assert len(res.error) == 300


def test_wrong_return_type_is_a_failure():
    res = run_all([fake_spec("a", lambda d: "oops")], None, "example.com")[0]
    assert res.status == "failed" and "TypeError" in res.error


def test_keyboard_interrupt_stops_the_scan():
    def stop(domain):
        raise KeyboardInterrupt

    results = run_all([fake_spec("a", stop), fake_spec("b", ok_run)], None, "example.com")
    assert len(results) == 1
    assert results[0].error == INTERRUPTED


def test_broken_callbacks_do_not_abort():
    def bad(*args):
        raise RuntimeError("ui")

    results = run_all([fake_spec("a", ok_run)], None, "example.com",
                      on_start=bad, on_result=bad)
    assert results[0].status == "ok"


def test_later_modules_see_previous_results():
    seen = []
    holder = {}

    def first(domain):
        return ModuleResult("x", "y", Status.OK)

    def second(domain):
        seen.append(len(holder["ctx"].results))
        return ModuleResult("x", "y", Status.OK)

    spec_b = fake_spec("b", second)
    spec_b.factory = lambda ctx: (holder.__setitem__("ctx", ctx) or SimpleNamespace(run=second))
    run_all([fake_spec("a", first), spec_b], None, "example.com")
    assert seen == [1]


# --- registry -------------------------------------------------------------

def test_real_specs_are_valid():
    validate_specs(registry.SPECS)


def _spec(id, requires=()):
    return ModuleSpec(id, id, "passive", "s", "finding", "High", lambda c: None,
                      requires=requires)


def test_validate_rejects_duplicates():
    with pytest.raises(ValueError):
        validate_specs([_spec("a"), _spec("a")])


def test_validate_rejects_unknown_dependency():
    with pytest.raises(ValueError):
        validate_specs([_spec("a", requires=("zzz",))])


def test_validate_rejects_dependency_listed_later():
    with pytest.raises(ValueError):
        validate_specs([_spec("a", requires=("b",)), _spec("b")])


def test_select_rejects_bad_input():
    with pytest.raises(ScanError):
        registry.select("bogus")
    with pytest.raises(ScanError):
        registry.select("all", only=["nope"])
    with pytest.raises(ScanError):
        registry.select("all", only=["dns"], exclude=["dns"])


def test_default_all_skips_opt_in_and_adds_dependents(monkeypatch):
    monkeypatch.setattr(registry, "is_available", lambda spec: True)
    ids = [s.id for s in registry.select("all")]
    assert "rustscan" not in ids
    assert ids.index("fingerprint") < ids.index("searchsploit")


def test_excluding_dependency_drops_dependent(monkeypatch):
    monkeypatch.setattr(registry, "is_available", lambda spec: True)
    ids = [s.id for s in registry.select("all", exclude=["fingerprint"])]
    assert "searchsploit" not in ids


def test_unavailable_tool_is_not_selected(monkeypatch):
    monkeypatch.setattr(registry, "is_available", lambda spec: not spec.executable)
    assert "searchsploit" not in [s.id for s in registry.select("all")]
    assert {s.id for s in registry.unavailable("all")} == {"rustscan", "searchsploit"}


def test_security_headers_is_opt_in_and_requires_authorisation():
    assert "security_headers" not in [s.id for s in registry.select("all")]
    with pytest.raises(ScanError, match="active modules require confirmation"):
        prepare("example.com", "all", ["security_headers"], None, False)
    _, specs = prepare("example.com", "all", ["security_headers"], None, True)
    assert [spec.id for spec in specs] == ["security_headers"]
# osint/runner.py
import time
from datetime import datetime, timezone

from osint.base import ScanContext
from osint.models import ModuleResult


def run_all(specs, client, domain, on_start=None, on_result=None, module_options=None):
    results = []
    context = ScanContext(client, module_options)
    ordered_specs = sorted(specs, key=lambda spec: spec.id == "searchsploit")
    for spec in ordered_specs:
        if on_start:
            on_start(spec)
        started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        t0 = time.time()
        try:
            res = spec.factory(context).run(domain)
        except Exception as exc:
            res = ModuleResult(spec.title, spec.phase, "failed",
                               error=f"{type(exc).__name__}: {exc}"[:300])
        res.name, res.id, res.source, res.kind = spec.title, spec.id, spec.source, spec.kind
        res.confidence = spec.confidence if res.status == "ok" else "n/a"
        res.elapsed = round(time.time() - t0, 2)
        res.started_at = started
        results.append(res)
        context.results.append(res)
        if on_result:
            on_result(res)
    return results
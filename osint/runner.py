# osint/runner.py
import logging
import time
from datetime import datetime, timezone

from osint.base import ScanContext
from osint.models import ModuleResult, ScanError

INTERRUPTED = "interrupted by user"
log = logging.getLogger(__name__)


def order_by_dependencies(specs):
    """Orden estable: cada módulo va después de los módulos de `requires` presentes."""
    pending = list(specs)
    present = {spec.id for spec in pending}
    ordered, done = [], set()
    while pending:
        for spec in pending:
            needs = {dep for dep in getattr(spec, "requires", ()) if dep in present}
            if needs <= done:
                ordered.append(spec)
                done.add(spec.id)
                pending.remove(spec)
                break
        else:
            raise ScanError("circular module dependency")
    return ordered


def _notify(callback, *args):
    if not callback:
        return
    try:
        callback(*args)
    except Exception:  # una UI rota no debe abortar el escaneo
        log.debug("callback failed", exc_info=True)


def _execute(spec, context, domain):
    """Ejecuta un módulo y devuelve (resultado, interrumpido)."""
    try:
        res = spec.factory(context).run(domain)
        if not isinstance(res, ModuleResult):
            raise TypeError(f"module returned {type(res).__name__}, expected ModuleResult")
        return res, False
    except KeyboardInterrupt:
        return ModuleResult(spec.title, spec.phase, "failed", error=INTERRUPTED), True
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"[:300]
        return ModuleResult(spec.title, spec.phase, "failed", error=error), False


def run_all(specs, client, domain, on_start=None, on_result=None, module_options=None):
    results = []
    context = ScanContext(client, module_options)
    for spec in order_by_dependencies(specs):
        _notify(on_start, spec)
        started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        t0 = time.perf_counter()
        res, interrupted = _execute(spec, context, domain)
        res.name, res.id, res.source, res.kind = spec.title, spec.id, spec.source, spec.kind
        res.confidence = spec.confidence if res.status == "ok" else "n/a"
        res.elapsed = round(time.perf_counter() - t0, 2)
        res.started_at = started
        results.append(res)
        context.results.append(res)
        _notify(on_result, res)
        if interrupted:
            break
    return results
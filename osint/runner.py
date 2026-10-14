# osint/runner.py
import logging
import time
from datetime import datetime, timezone

from osint.base import ScanContext
from osint.models import ModuleResult

INTERRUPTED = "interrupted by user"
log = logging.getLogger(__name__)


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
    for spec in specs:  # el orden lo define el registro (dependencias primero)
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
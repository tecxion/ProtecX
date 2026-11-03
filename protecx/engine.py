"""Orquestador: ejecuta los escáneres elegidos y devuelve el informe."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Callable

from . import config, explain
from .context import SCANNER_ORDER, ScanContext, ScanOptions
from .models import ScanReport
from .scanners import SCANNERS
from .scanners.inspector import FileInspector
from .signatures import SignatureStore, YaraEngine
from .utils import host_info, now_iso

_MAX_YARA_WARNINGS = 5


def _preflight_warnings(report: ScanReport, yara_engine: YaraEngine) -> None:
    """Avisos sobre limitaciones del análisis que el usuario debe conocer."""
    if not report.host["admin"]:
        report.warnings.append("Sin privilegios de administrador/root: no se verán todos los procesos, "
                               "sockets ni archivos. Para un análisis completo, ejecútalo con privilegios.")

    last = report.signatures.get("last_update")
    if not last:
        report.warnings.append("Las firmas nunca se han actualizado: solo se usan las reglas integradas. "
                               "Ejecuta «protecx update».")
    else:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(last)
        if age.days >= config.STALE_DB_DAYS:
            report.warnings.append(f"Las firmas tienen {age.days} días. Ejecuta «protecx update».")

    if not yara_engine.available:
        report.warnings.append("yara-python no está instalado: sin detección por reglas YARA "
                               "(pip install yara-python).")
    elif not yara_engine.loaded:
        report.warnings.append("No se pudieron cargar las reglas YARA.")
    for message in yara_engine.warnings[:_MAX_YARA_WARNINGS]:
        report.warnings.append(message)
    hidden = len(yara_engine.warnings) - _MAX_YARA_WARNINGS
    if hidden > 0:
        report.warnings.append(f"…y {hidden} reglas YARA más descartadas por errores de sintaxis.")


def run_scan(options: ScanOptions, store: SignatureStore, yara_engine: YaraEngine,
             progress: Callable[..., None] = lambda message, **_: None) -> ScanReport:
    report = ScanReport(host=host_info(), started_at=now_iso(), signatures=store.info())
    if yara_engine.available and not yara_engine.loaded:
        progress("Cargando reglas YARA (la primera vez tarda)…")
        yara_engine.load()
    _preflight_warnings(report, yara_engine)

    ctx = ScanContext(options, store, yara_engine, FileInspector(store, yara_engine), report, progress)
    selected = [name for name in SCANNER_ORDER if name in options.scanners]
    for number, name in enumerate(selected, start=1):
        scanner = SCANNERS[name](ctx)
        progress(scanner.label, stage=number, stages=len(selected))
        started = time.monotonic()
        try:
            for finding in scanner.run():
                report.findings.append(finding)
        except Exception as exc:  # noqa: BLE001 - un escáner roto no debe tirar el análisis entero
            report.warnings.append(f"{scanner.label}: el análisis se interrumpió ({exc.__class__.__name__}: {exc})")
        report.stats.setdefault(name, {})["segundos"] = round(time.monotonic() - started, 1)

    explain.enrich(report)
    report.finished_at = now_iso()
    return report

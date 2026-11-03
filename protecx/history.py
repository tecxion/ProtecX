"""Comparación con el análisis anterior: qué hallazgos son nuevos, cuáles siguen y cuáles se resolvieron.

Se compara con el informe JSON más reciente de la carpeta de informes que haya ejecutado
al menos los mismos módulos (un análisis solo de red no sirve de referencia para uno completo).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from .models import ScanReport

# Datos estables de un hallazgo (el pid o los puertos efímeros cambian de un análisis a otro)
_KEYS = ("ruta", "ejecutable", "nombre", "proceso", "remoto", "puerto", "dominio", "ubicacion",
         "interfaz", "biblioteca", "regla", "firma", "tipo")


def fingerprint(scanner: str, title: str, evidence: dict[str, Any]) -> tuple:
    return (scanner, title, tuple(str(evidence.get(key, "")).lower() for key in _KEYS))


def find_previous(report_dir: Path, scanners: set[str]) -> Optional[dict[str, Any]]:
    for path in sorted(report_dir.glob("protecx-*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and scanners <= set(data.get("stats", {})):
            return data
    return None


def compare(report: ScanReport, report_dir: Path) -> None:
    """Marca `is_new` en cada hallazgo y rellena `report.comparison`. Sin informe previo no hace nada."""
    scanners = set(report.stats)
    previous = find_previous(report_dir, scanners)
    if previous is None:
        return
    before = {fingerprint(f["scanner"], f["title"], f.get("evidence", {})): f for f in previous.get("findings", [])}
    now = set()
    for finding in report.findings:
        key = fingerprint(finding.scanner, finding.title, finding.evidence)
        finding.is_new = key not in before
        now.add(key)
    resolved = [f for key, f in before.items() if key not in now and f["scanner"] in scanners]
    report.comparison = {
        "previous": previous.get("started_at", ""),
        "new": sum(1 for f in report.findings if f.is_new),
        "unchanged": sum(1 for f in report.findings if not f.is_new),
        "resolved": [{"title": f["title"], "severity_label": f.get("severity_label", ""), "scanner": f["scanner"],
                      "ruta": f.get("evidence", {}).get("ruta", "")} for f in resolved],
    }

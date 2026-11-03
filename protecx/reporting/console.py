"""Resumen legible en la terminal."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TextIO

from ..models import ScanReport, Severity

_COLORS = {Severity.CRITICAL: "31;1", Severity.HIGH: "31", Severity.MEDIUM: "33",
           Severity.LOW: "34", Severity.INFO: "90"}
_MAX_LISTED = 15


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def print_summary(report: ScanReport, files: list[Path], stream: TextIO = sys.stdout) -> None:
    color = stream.isatty() and "NO_COLOR" not in os.environ
    counts = report.counts()
    out = lambda line="": print(line, file=stream)  # noqa: E731

    out()
    out(f"Análisis de {report.host['hostname']} ({report.host['os']})")
    out("  " + "  ".join(_paint(f"{sev.label}: {counts[sev.name.lower()]}", _COLORS[sev], color)
                         for sev in sorted(Severity, reverse=True)))

    findings = report.sorted_findings()
    cmp = report.comparison
    if cmp:
        out("  " + _paint(f"Desde el análisis anterior ({cmp['previous'][:16].replace('T', ' ')}): "
                          f"{cmp['new']} nuevos, {cmp['unchanged']} sin cambios, {len(cmp['resolved'])} resueltos", "36", color))
    for finding in findings[:_MAX_LISTED]:
        tag = _paint(f"[{finding.severity.label}]", _COLORS[finding.severity], color)
        new = _paint(" NUEVO", "1;35", color) if finding.is_new else ""
        out(f"  {tag}{new} {finding.title}")
    if len(findings) > _MAX_LISTED:
        out(f"  … y {len(findings) - _MAX_LISTED} más en el informe.")
    if not findings:
        out("  No se encontraron amenazas conocidas.")

    for warning in report.warnings:
        out(_paint(f"  Aviso: {warning}", "33", color))
    for path in files:
        out(f"Informe: {path}")

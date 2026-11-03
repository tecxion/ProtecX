"""Modelos de datos compartidos por escáneres, motor e informes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional


class Severity(IntEnum):
    """Gravedad de un hallazgo. Ordenable: CRITICAL > HIGH > ... > INFO."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return _SEVERITY_LABELS[self]


_SEVERITY_LABELS = {
    Severity.INFO: "Info",
    Severity.LOW: "Bajo",
    Severity.MEDIUM: "Medio",
    Severity.HIGH: "Alto",
    Severity.CRITICAL: "Crítico",
}


@dataclass
class Finding:
    """Un indicio detectado por un escáner."""

    scanner: str
    severity: Severity
    title: str
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    # Rellenados al final del análisis por explain.enrich()
    explanation: dict[str, Any] = field(default_factory=dict)  # qué es / por qué importa / qué hacer
    subject: dict[str, str] = field(default_factory=dict)      # ficha legible del archivo o proceso
    is_new: Optional[bool] = None   # None = no hay análisis anterior con el que comparar

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "severity": self.severity.name.lower(),
            "severity_label": self.severity.label,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "explanation": self.explanation,
            "subject": self.subject,
            "is_new": self.is_new,
        }


@dataclass
class ScanReport:
    """Resultado completo de un análisis."""

    host: dict[str, Any]
    started_at: str
    finished_at: str = ""
    signatures: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    # Tablas informativas (puertos, conexiones, persistencia...): clave -> filas
    inventory: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, dict[str, Any]] = field(default_factory=dict)
    comparison: dict[str, Any] = field(default_factory=dict)  # lo rellena history.compare()

    def counts(self) -> dict[str, int]:
        counts = {sev.name.lower(): 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.name.lower()] += 1
        return counts

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity, f.is_new is not True, f.scanner, f.title))

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "signatures": self.signatures,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "inventory": self.inventory,
            "warnings": self.warnings,
            "stats": self.stats,
            "comparison": self.comparison,
        }

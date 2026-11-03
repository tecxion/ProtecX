"""Clase base de los escáneres: reduce el código repetido en cada uno."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterator

from ..context import ScanContext
from ..models import Finding, Severity


class Scanner(ABC):
    name = ""     # identificador interno ('processes')
    label = ""    # nombre legible para informes ('Procesos')

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx

    @abstractmethod
    def run(self) -> Iterator[Finding]:
        """Genera los hallazgos. Los errores recuperables se anotan con warn()."""

    # -- ayudas para las subclases -----------------------------------------
    def finding(self, severity: Severity, title: str, detail: str = "",
                recommendation: str = "", **evidence: Any) -> Finding:
        return Finding(self.name, severity, title, detail, evidence, recommendation)

    def warn(self, message: str) -> None:
        self.ctx.report.warnings.append(f"{self.label}: {message}")

    def add_inventory(self, key: str, rows: list[dict[str, Any]]) -> None:
        self.ctx.report.inventory.setdefault(key, []).extend(rows)

    def stat(self, key: str, value: Any) -> None:
        self.ctx.report.stats.setdefault(self.name, {})[key] = value

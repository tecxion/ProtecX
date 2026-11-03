"""Escáner de persistencia: ¿qué se ejecuta solo al arrancar o por horario?

El recolector enumera (collectors/autostart.py); aquí se juzga cada entrada
con las reglas compartidas y se comprueba el binario al que apunta.
"""

from __future__ import annotations

import os
from typing import Iterator

from .. import heuristics
from ..collectors.autostart import AutostartEntry, collect
from ..models import Finding, Severity
from .base import Scanner

_INVENTORY_COMMAND_CHARS = 200


class PersistenceScanner(Scanner):
    name = "persistence"
    label = "Persistencia"

    def run(self) -> Iterator[Finding]:
        count = 0
        for entry in collect():
            count += 1
            self.add_inventory("persistence", [{
                "tipo": entry.kind, "ubicacion": entry.location,
                "comando": entry.command[:_INVENTORY_COMMAND_CHARS],
            }])
            yield from self._evaluate(entry)
        self.stat("entradas_de_arranque", count)

    def _evaluate(self, entry: AutostartEntry) -> Iterator[Finding]:
        executable = heuristics.extract_executable(entry.command) if entry.command else None
        evidence = {"tipo": entry.kind, "ubicacion": entry.location,
                    "comando": entry.command[:_INVENTORY_COMMAND_CHARS], "ejecutable": executable or ""}

        reasons: list[tuple[Severity, str]] = []
        if entry.base_severity > Severity.INFO:
            reasons.append((entry.base_severity, entry.note or "entrada de riesgo"))
        reasons += heuristics.evaluate_command(entry.content or entry.command)
        if executable and (location := heuristics.suspicious_location(executable)):
            reasons.append((max(location[0], Severity.MEDIUM), f"ejecuta un programa en {location[1]}"))

        if reasons:
            severity = max(sev for sev, _ in reasons)
            yield self.finding(
                severity, f"Arranque automático sospechoso ({entry.kind})",
                "; ".join(dict.fromkeys(why for _, why in reasons)).capitalize() + ".",
                "Si no reconoces esta entrada, desactívala y comprueba el programa al que apunta.",
                **evidence)

        if executable and os.path.isfile(executable):
            yield from self.ctx.inspector.inspect(executable).findings(self.name, f"arranque: {entry.kind}")

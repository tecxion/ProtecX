"""Escritura de informes en disco (JSON para máquinas, HTML para personas)."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Iterable

from ..models import ScanReport, Severity

_TEMPLATE = Path(__file__).with_name("report_template.html")

INVENTORY_TITLES = {
    "processes": "Procesos en ejecución",
    "listening": "Puertos en escucha",
    "connections": "Conexiones activas",
    "persistence": "Arranque automático",
}
SCANNER_LABELS = {
    "system": "Sistema", "processes": "Procesos", "network": "Red",
    "persistence": "Persistencia", "files": "Archivos",
}


def render_html(report: ScanReport) -> str:
    payload = report.to_dict()
    payload["inventory_titles"] = INVENTORY_TITLES
    payload["severity_by_label"] = {sev.label: sev.name.lower() for sev in Severity}
    payload["scanner_labels"] = SCANNER_LABELS
    # Escapar '<' evita que una cadena maliciosa (p. ej. un nombre de proceso con
    # '</script>') cierre la etiqueta y ejecute código al abrir el informe.
    data = json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c")
    return _TEMPLATE.read_text(encoding="utf-8").replace("__REPORT_DATA__", data)


def write_reports(report: ScanReport, out_dir: Path, formats: Iterable[str]) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"protecx-{datetime.now():%Y%m%d-%H%M%S}"
    written = []
    for fmt in formats:
        path = out_dir / f"{stem}.{fmt}"
        content = (render_html(report) if fmt == "html"
                   else json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        path.write_text(content, encoding="utf-8")
        if os.name == "posix":
            path.chmod(0o600)  # el informe describe el equipo: solo para su dueño
        written.append(path)
    return written

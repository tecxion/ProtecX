"""Opciones de análisis y contexto compartido que reciben todos los escáneres."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .models import ScanReport

if TYPE_CHECKING:  # evita importaciones circulares en tiempo de ejecución
    from .scanners.inspector import FileInspector
    from .signatures import SignatureStore, YaraEngine

SCANNER_ORDER = ("system", "processes", "network", "persistence", "files")


@dataclass
class ScanOptions:
    mode: str = "quick"                       # 'quick' o 'full'
    paths: list[Path] = field(default_factory=list)   # vacío = rutas por defecto del modo
    scanners: tuple[str, ...] = SCANNER_ORDER
    yara_memory: bool = False                 # YARA sobre la memoria de procesos
    use_clamav: bool = False
    monitor_seconds: int = 0                  # observar la red N segundos (beaconing)
    max_file_mb: int = 100
    workers: int = field(default_factory=lambda: min(8, max(2, os.cpu_count() or 2)))


@dataclass
class ScanContext:
    options: ScanOptions
    store: "SignatureStore"
    yara: "YaraEngine"
    inspector: "FileInspector"
    report: ScanReport
    progress: Callable[..., None] = lambda message, **_: None  # ver reporting/progress.py

"""Registro de escáneres disponibles, por nombre."""

from __future__ import annotations

from .files import FileScanner
from .network import NetworkScanner
from .persistence import PersistenceScanner
from .processes import ProcessScanner
from .system import SystemScanner

SCANNERS = {cls.name: cls for cls in (SystemScanner, ProcessScanner, NetworkScanner,
                                      PersistenceScanner, FileScanner)}

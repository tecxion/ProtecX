"""Integración opcional con ClamAV si está instalado en el sistema.

No se descargan sus bases a mano: el proyecto ClamAV exige usar `freshclam`
(descargas directas con scripts son bloqueadas por su CDN).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Optional

from ..config import IS_MAC, IS_WINDOWS


def _install_dirs() -> list[Path]:
    """Sitios habituales de instalación: el instalador de Windows no añade ClamAV al PATH."""
    if IS_WINDOWS:
        return [Path(os.environ.get(var, default)) / "ClamAV"
                for var, default in (("ProgramFiles", r"C:\Program Files"), ("ProgramFiles(x86)", r"C:\Program Files (x86)"))
                ] + [Path(r"C:\ClamAV")]
    return [Path("/opt/homebrew/bin"), Path("/usr/local/bin")] if IS_MAC else []


def find_tool(name: str) -> Optional[str]:
    """Ruta de `clamscan`/`freshclam`: primero el PATH, luego las carpetas de instalación habituales."""
    found = shutil.which(name)
    if found:
        return found
    for folder in _install_dirs():
        candidate = folder / (name + (".exe" if IS_WINDOWS else ""))
        if candidate.is_file():
            return str(candidate)
    return None


class ClamAV:
    def __init__(self) -> None:
        self.scan_exe = find_tool("clamscan")
        self.update_exe = find_tool("freshclam")

    @property
    def available(self) -> bool:
        return self.scan_exe is not None

    def update(self, timeout: int = 600, prefix: tuple[str, ...] = ()) -> tuple[bool, str]:
        """Ejecuta freshclam (`prefix` = ('sudo',) en Linux). Puede requerir permisos de administrador."""
        if not self.update_exe:
            return False, "freshclam no está instalado"
        try:
            result = subprocess.run([*prefix, self.update_exe], capture_output=True, text=True,
                                    timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, str(exc)
        tail = (result.stdout or result.stderr).strip().splitlines()[-1:]
        return result.returncode == 0, tail[0] if tail else ""

    def scan(self, paths: Iterable[Path], timeout: Optional[int] = 3600) -> list[tuple[str, str]]:
        """Devuelve [(ruta, firma)] de lo infectado. Lista vacía si no hay nada o falla."""
        if not self.scan_exe:
            return []
        cmd = [self.scan_exe, "-r", "--infected", "--no-summary",
               "--follow-file-symlinks=0", "--follow-dir-symlinks=0", *map(str, paths)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError):
            return []
        hits = []
        for line in result.stdout.splitlines():
            if line.endswith(" FOUND") and ": " in line:
                path, signature = line[:-6].rsplit(": ", 1)
                hits.append((path, signature))
        return hits

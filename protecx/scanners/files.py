"""Escáner de archivos: hashes conocidos, reglas YARA, scripts y trucos de nombre.

Para ser rápido no analiza "todo": solo ejecutables, scripts y documentos con
macros (por extensión, por permisos de ejecución en Unix o por cabecera).
"""

from __future__ import annotations

import os
import re
import tempfile
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Iterable, Iterator

import psutil

from .. import heuristics
from ..config import IS_MAC, IS_WINDOWS, app_dir
from ..models import Finding, Severity
from ..signatures.clamav import ClamAV
from ..utils import exec_kind, normalize_path
from .base import Scanner

RISKY_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".sys", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".lnk", ".jar", ".sh", ".py", ".pl", ".so", ".dylib",
    ".command", ".docm", ".xlsm", ".pptm", ".iso",
}
SCRIPT_EXTENSIONS = {".ps1", ".sh", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".py", ".pl", ".command"}
# Windows crea aquí un «<archivo>.<ext>.lnk» por cada archivo que abres: no es engaño, es el historial.
_RECENT_FOLDER = "/microsoft/windows/recent/"


def _is_windows_recent_shortcut(path: str) -> bool:
    return path.lower().endswith(".lnk") and _RECENT_FOLDER in path.replace("\\", "/").lower()


# 'factura.pdf.exe': un documento que en realidad es un ejecutable
_DOUBLE_EXTENSION = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip|rar)\.(exe|scr|bat|cmd|com|js|vbs|ps1|hta|lnk)$", re.I)
_VIRTUAL_FS = {"proc", "sysfs", "devfs", "devpts", "cgroup", "cgroup2", "autofs", "squashfs",
               "nfs", "nfs4", "cifs", "smbfs", "fuse.sshfs", "iso9660"}
_SCRIPT_READ_BYTES = 64 * 1024
_PROGRESS_EVERY = 500


def default_roots(mode: str) -> list[Path]:
    """Carpetas a analizar según el modo: 'quick' (zonas de riesgo) o 'full' (todo)."""
    if mode == "full":
        if IS_WINDOWS:
            return [Path(p.mountpoint) for p in psutil.disk_partitions(all=False)
                    if p.fstype and "cdrom" not in p.opts]
        return [Path("/")]

    home = Path.home()
    candidates = [tempfile.gettempdir(), home / "Downloads", home / "Desktop", home / "Documents"]
    if IS_WINDOWS:
        env = os.environ.get
        candidates += [env("APPDATA"), env("PROGRAMDATA"), r"C:\Users\Public", r"C:\Windows\Temp"]
    else:
        candidates += ["/tmp", "/var/tmp", "/dev/shm", "/usr/local/bin", home / ".local" / "bin"]
        if IS_MAC:
            candidates += [home / "Library" / "LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"]
    roots = {Path(c) for c in candidates if c}
    return sorted(p for p in roots if p.is_dir())


def _skip_dirs() -> set[str]:
    """Rutas (normalizadas) que no tiene sentido recorrer."""
    # Código, tests, informes y entorno de ProtecX: contienen a propósito las cadenas de ataque
    # que busca y se marcarían a sí mismos. shortcut: se omiten por nombre; si hace falta, comprobar firma/hash.
    skip = {normalize_path(str(app_dir() / name)) for name in ("protecx", "tests", "reports", ".venv")}
    if IS_WINDOWS:
        skip.add(normalize_path(os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "WinSxS")))
    else:
        skip.update({"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/lib/containers"})
        skip.discard("/dev/shm")
        if IS_MAC:
            skip.update({"/system/volumes/data/.fseventsd", "/volumes"})
    try:
        skip.update(normalize_path(p.mountpoint) for p in psutil.disk_partitions(all=True)
                    if p.fstype in _VIRTUAL_FS and p.mountpoint not in ("/", ""))
    except Exception:  # noqa: BLE001 - psutil puede fallar según el sistema
        pass
    return skip


class FileScanner(Scanner):
    name = "files"
    label = "Archivos"

    def run(self) -> Iterator[Finding]:
        opts = self.ctx.options
        roots = [Path(p) for p in opts.paths] or default_roots(opts.mode)
        self.stat("carpetas", [str(r) for r in roots])
        scanned = next_report = 0

        with ThreadPoolExecutor(max_workers=opts.workers) as pool:
            pending: set = set()
            for path in self._candidates(roots):
                pending.add(pool.submit(self._inspect, path))
                if len(pending) >= opts.workers * 4:  # acota la memoria en discos grandes
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    scanned += len(done)
                    yield from self._collect(done)
                    if scanned >= next_report:
                        self.ctx.progress("archivos", count=scanned)
                        next_report = scanned + _PROGRESS_EVERY
            done, _ = wait(pending)
            scanned += len(done)
            yield from self._collect(done)

        self.ctx.progress("archivos", count=scanned)
        self.stat("archivos_analizados", scanned)
        if opts.use_clamav:
            yield from self._clamav(roots)

    # -- recorrido ---------------------------------------------------------
    def _candidates(self, roots: Iterable[Path]) -> Iterator[str]:
        max_bytes = self.ctx.options.max_file_mb * 1024 * 1024
        skip = _skip_dirs()
        stack = [str(Path(r).resolve()) for r in roots]  # absolutas: así casan con las rutas a omitir
        while stack:
            directory = stack.pop()
            try:
                scan = os.scandir(directory)
            except OSError:
                continue  # sin permisos o carpeta desaparecida
            with scan:
                for entry in scan:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if normalize_path(entry.path) not in skip:
                                stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False) and self._is_candidate(entry, max_bytes):
                            yield entry.path
                    except OSError:
                        continue

    @staticmethod
    def _is_candidate(entry: os.DirEntry, max_bytes: int) -> bool:
        st = entry.stat(follow_symlinks=False)
        if not 0 < st.st_size <= max_bytes:
            return False
        if os.path.splitext(entry.name)[1].lower() in RISKY_EXTENSIONS:
            return True
        return not IS_WINDOWS and bool(st.st_mode & 0o111)  # ejecutable sin extensión

    # -- análisis de un archivo (se ejecuta en hilos) ------------------------
    def _inspect(self, path: str) -> list[Finding]:
        findings = self.ctx.inspector.inspect(path).findings(self.name)
        name = os.path.basename(path)
        ext = os.path.splitext(name)[1].lower()
        kind = exec_kind(path)

        if _DOUBLE_EXTENSION.search(name) and not _is_windows_recent_shortcut(path):
            findings.append(self.finding(
                Severity.HIGH, "Doble extensión engañosa",
                "El nombre simula un documento, pero es ejecutable.",
                "No lo abras. Compruébalo con un segundo motor antes de borrarlo.", ruta=path))

        if kind in ("pe", "elf", "macho"):
            findings += self._executable_location(path, name)
        if kind == "script" or ext in SCRIPT_EXTENSIONS:
            findings += self._script_content(path)
        return findings

    def _executable_location(self, path: str, name: str) -> list[Finding]:
        location = heuristics.suspicious_location(path)
        if not location:
            return []
        severity, why = location
        if name.startswith(".") and not IS_WINDOWS:
            severity = Severity.HIGH  # ejecutable oculto en una carpeta temporal
            why = f"{why}, archivo oculto"
        elif severity < Severity.HIGH:
            severity = Severity.LOW  # instaladores legítimos también pasan por /tmp o Temp
        return [self.finding(severity, f"Ejecutable en {why}",
                             "Los programas legítimos rara vez residen aquí de forma permanente.",
                             "Comprueba su origen y su hash en un servicio de reputación.", ruta=path)]

    def _script_content(self, path: str) -> list[Finding]:
        try:
            with open(path, "r", errors="replace") as handle:
                text = handle.read(_SCRIPT_READ_BYTES)
        except OSError:
            return []
        return [self.finding(min(severity, Severity.HIGH), f"Script sospechoso: {why}",
                             "Patrón de comandos habitual en malware o administración maliciosa.",
                             "Revisa el contenido del script antes de ejecutarlo.", ruta=path)
                for severity, why in heuristics.evaluate_command(text)]

    @staticmethod
    def _collect(futures) -> Iterator[Finding]:
        for future in futures:
            yield from future.result()

    # -- ClamAV opcional ------------------------------------------------------
    def _clamav(self, roots: list[Path]) -> Iterator[Finding]:
        clam = ClamAV()
        if not clam.available:
            self.warn("ClamAV no está instalado; se omitió su análisis")
            return
        self.ctx.progress("Ejecutando ClamAV…")
        for path, signature in clam.scan(roots):
            yield self.finding(Severity.CRITICAL, f"ClamAV: {signature}",
                               "Detectado por el motor ClamAV.",
                               "Aísla el archivo y verifícalo antes de eliminarlo.", ruta=path, firma=signature)

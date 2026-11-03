"""Escáner de procesos en ejecución.

Busca binarios conocidos como malware, procesos que se hacen pasar por otros,
ejecución desde carpetas temporales o memoria, y líneas de comandos típicas
de ataques (reverse shells, PowerShell codificado...).
"""

from __future__ import annotations

import os
from typing import Any, Iterator, Optional

import psutil

from .. import heuristics
from ..config import IS_LINUX
from ..models import Finding, Severity
from ..utils import normalize_path
from .base import Scanner

_PROC_ATTRS = ["pid", "name", "exe", "cmdline", "username"]
_SYSTEM_BIN_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/lib/",
                        "/windows/system32/", "/system/", "/usr/libexec/")


def _is_system_binary(path: str) -> bool:
    """Binarios del sistema: se comprueba su hash, pero no se pasan por YARA (lento y ruidoso)."""
    norm = normalize_path(path).split(":", 1)[-1]
    return norm.startswith(_SYSTEM_BIN_PREFIXES)


class ProcessScanner(Scanner):
    name = "processes"
    label = "Procesos"

    def run(self) -> Iterator[Finding]:
        me = os.getpid()
        reported_binaries: set[str] = set()  # un binario con 10 procesos se avisa una sola vez
        rows = []
        for proc in psutil.process_iter(_PROC_ATTRS):
            info = proc.info
            if info["pid"] in (0, me):
                continue
            rows.append({"pid": info["pid"], "proceso": info.get("name") or "",
                         "usuario": info.get("username") or "", "ruta": info.get("exe") or ""})
            yield from self._check(proc, info, reported_binaries)
        self.add_inventory("processes", rows)
        self.stat("procesos_analizados", len(rows))

    # -- comprobaciones por proceso ----------------------------------------
    def _check(self, proc: psutil.Process, info: dict[str, Any], reported: set[str]) -> Iterator[Finding]:
        pid, name = info["pid"], info.get("name") or ""
        exe, cmdline = info.get("exe") or "", info.get("cmdline") or []
        subject = {"pid": pid, "nombre": name, "ruta": exe, "usuario": info.get("username"),
                   "comando": " ".join(cmdline)[:500]}

        lowered = name.lower()
        if lowered in heuristics.KNOWN_BAD_NAMES or lowered.removesuffix(".exe") in heuristics.KNOWN_BAD_NAMES:
            yield self.finding(Severity.HIGH, f"Herramienta maliciosa o no deseada: {name}",
                               "El nombre del proceso corresponde a un minero o herramienta de robo de credenciales.",
                               "Finaliza el proceso y localiza cómo se instaló.", **subject)

        if exe:
            yield from self._check_binary(pid, name, exe, cmdline, subject, reported)

        for severity, why in heuristics.evaluate_command(" ".join(cmdline)):
            yield self.finding(severity, f"Línea de comandos sospechosa: {why}",
                               "El proceso se lanzó con argumentos típicos de un ataque.",
                               "Revisa quién lo inició (proceso padre) y finalízalo si no lo reconoces.", **subject)

        if IS_LINUX:
            yield from self._check_linux_runtime(proc, pid, subject)

        if self.ctx.options.yara_memory and self.ctx.yara.loaded:
            for hit in self.ctx.yara.scan_pid(pid):
                yield self.finding(hit.severity, f"Regla YARA «{hit.rule}» en la memoria del proceso",
                                   hit.description, "Es un indicio fuerte: puede haber código inyectado.",
                                   regla=hit.rule, puntuacion=hit.score, **subject)

    def _check_binary(self, pid: int, name: str, exe: str, cmdline: list[str],
                      subject: dict[str, Any], reported: set[str]) -> Iterator[Finding]:
        if heuristics.is_masquerading(name, exe):
            yield self.finding(Severity.HIGH, f"{name} se ejecuta desde una carpeta inusual",
                               "Es un proceso del sistema, pero su binario no está donde debería: "
                               "técnica habitual para ocultar malware.",
                               "Finaliza el proceso y comprueba el archivo.", **subject)

        if heuristics.is_fake_kernel_thread(cmdline, exe):
            yield self.finding(Severity.HIGH, "Proceso que finge ser un hilo del kernel",
                               "Un hilo real del kernel no tiene binario en disco.",
                               "Investiga el binario y su origen.", **subject)

        location = heuristics.suspicious_location(exe)
        if location:
            yield self.finding(max(location[0], Severity.MEDIUM), f"Proceso ejecutándose desde {location[1]}",
                               "Los programas legítimos no suelen ejecutarse desde aquí.",
                               "Comprueba el origen del archivo.", **subject)

        if exe in reported or not os.path.isfile(exe):
            return
        reported.add(exe)
        inspection = self.ctx.inspector.inspect(exe, use_yara=not _is_system_binary(exe))
        yield from inspection.findings(self.name, f"proceso {name}, PID {pid}")

    def _check_linux_runtime(self, proc: psutil.Process, pid: int, subject: dict[str, Any]) -> Iterator[Finding]:
        state = self._exe_state(pid)
        if state == "memfd":
            yield self.finding(Severity.HIGH, "Proceso ejecutándose desde memoria anónima (memfd)",
                               "Técnica 'fileless': el programa nunca toca el disco.",
                               "Investiga el proceso y su proceso padre.", **subject)
        elif state == "deleted":
            risky = heuristics.suspicious_location(subject["ruta"]) is not None
            yield self.finding(Severity.HIGH if risky else Severity.MEDIUM,
                               "El binario del proceso fue borrado del disco",
                               "Puede deberse a una actualización pendiente de reinicio. Si no has "
                               "actualizado nada, es una técnica antiforense habitual.",
                               "Reinicia el servicio; si reaparece, investígalo.", **subject)

        try:
            preload = proc.environ().get("LD_PRELOAD")
        except (psutil.Error, OSError):
            preload = None  # sin permisos para leer el entorno de este proceso
        if preload:
            yield self.finding(Severity.MEDIUM, "Proceso con LD_PRELOAD",
                               "Carga una biblioteca antes que las del sistema (técnica de rootkits "
                               "de espacio de usuario).", "Revisa la biblioteca indicada.",
                               biblioteca=preload, **subject)

    @staticmethod
    def _exe_state(pid: int) -> Optional[str]:
        try:
            target = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return None
        if target.startswith("/memfd:"):
            return "memfd"
        return "deleted" if target.endswith(" (deleted)") else None

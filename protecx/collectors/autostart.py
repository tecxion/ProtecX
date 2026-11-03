"""Enumera los puntos de arranque automático (persistencia) de cada sistema.

Este módulo solo *recolecta* entradas; decidir si son sospechosas es trabajo
del escáner de persistencia. Cada función `_...` cubre un mecanismo concreto.
"""

from __future__ import annotations

import csv
import os
import plistlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..config import IS_LINUX, IS_MAC, IS_WINDOWS
from ..models import Severity
from ..utils import run_command

_MAX_READ = 256 * 1024
_ENV_ASSIGNMENT = re.compile(r"^\w+=")


@dataclass
class AutostartEntry:
    kind: str                              # 'Run (HKCU)', 'cron', 'systemd'...
    location: str                          # clave de registro, archivo o tarea
    command: str = ""                      # lo que se ejecuta (se muestra en el informe)
    content: str = ""                      # texto completo a analizar (perfiles de shell)
    base_severity: Severity = Severity.INFO
    note: str = ""                         # por qué la propia entrada ya es sospechosa


def collect() -> Iterator[AutostartEntry]:
    """Todas las entradas de arranque del sistema actual."""
    if IS_WINDOWS:
        yield from _windows()
    else:
        yield from _unix_common()
        if IS_LINUX:
            yield from _linux()
        elif IS_MAC:
            yield from _macos()


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")[:_MAX_READ]
    except OSError:
        return ""


def _glob(folder: Path, pattern: str = "*") -> list[Path]:
    """Archivos de una carpeta; vacío si no existe o no hay permiso (no aborta el análisis)."""
    try:
        return sorted(folder.glob(pattern)) if folder.is_dir() else []
    except OSError:
        return []


def _home_dirs() -> list[Path]:
    base = Path("/Users") if IS_MAC else Path("/home")
    homes = [Path("/root")] if IS_LINUX else []
    try:
        homes += [p for p in base.iterdir() if p.is_dir()]
    except OSError:
        pass
    return homes


# ===========================================================================
# Windows
# ===========================================================================
def _windows() -> Iterator[AutostartEntry]:
    try:
        import winreg  # type: ignore
    except ImportError:
        return
    yield from _win_run_keys(winreg)
    yield from _win_winlogon(winreg)
    yield from _win_ifeo(winreg)
    yield from _win_startup_folders()
    yield from _win_scheduled_tasks()
    yield from _win_services()


def _reg_values(winreg, hive, subkey: str, view: int = 0) -> Iterator[tuple[str, str]]:
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view)
    except OSError:
        return
    with key:
        index = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(key, index)
            except OSError:
                return
            yield name, str(data)
            index += 1


def _win_run_keys(winreg) -> Iterator[AutostartEntry]:
    hives = ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU"))
    subkeys = (r"Software\Microsoft\Windows\CurrentVersion\Run",
               r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
    views = (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY)
    for hive, hive_name in hives:
        for subkey in subkeys:
            for view in views:
                for name, data in _reg_values(winreg, hive, subkey, view):
                    yield AutostartEntry(f"Run ({hive_name})", f"{hive_name}\\{subkey}\\{name}", data)


def _win_winlogon(winreg) -> Iterator[AutostartEntry]:
    subkey = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    expected = {"shell": lambda v: v.lower() == "explorer.exe",
                "userinit": lambda v: v.lower().rstrip(", ").endswith("userinit.exe")}
    for name, data in _reg_values(winreg, winreg.HKEY_LOCAL_MACHINE, subkey):
        check = expected.get(name.lower())
        if check and not check(data):
            yield AutostartEntry("Winlogon", f"HKLM\\{subkey}\\{name}", data, base_severity=Severity.MEDIUM,
                                 note=f"el valor {name} de Winlogon fue modificado")


def _win_ifeo(winreg) -> Iterator[AutostartEntry]:
    """Image File Execution Options: un 'Debugger' hace que Windows lance otro
    programa en lugar del original (secuestro de ejecutables)."""
    base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
    except OSError:
        return
    with root:
        index = 0
        while True:
            try:
                program = winreg.EnumKey(root, index)
            except OSError:
                return
            index += 1
            for name, data in _reg_values(winreg, winreg.HKEY_LOCAL_MACHINE, f"{base}\\{program}"):
                if name.lower() == "debugger" and "vsjitdebugger" not in data.lower():
                    yield AutostartEntry("IFEO Debugger", f"HKLM\\{base}\\{program}", data,
                                         base_severity=Severity.HIGH,
                                         note=f"{program} se redirige a otro programa")


def _win_startup_folders() -> Iterator[AutostartEntry]:
    suffix = Path("Microsoft/Windows/Start Menu/Programs/Startup")
    for var in ("APPDATA", "PROGRAMDATA"):
        folder = Path(os.environ.get(var, "")) / suffix
        for item in _glob(folder):
            if item.name.lower() != "desktop.ini":
                yield AutostartEntry("Carpeta Inicio", str(item), str(item))


def _win_scheduled_tasks() -> Iterator[AutostartEntry]:
    """schtasks en CSV. Se usan índices de columna porque los nombres de las
    cabeceras cambian con el idioma de Windows."""
    output = run_command(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=120)
    rows = list(csv.reader(output.splitlines()))
    if not rows:
        return
    header, task_name, task_run = rows[0], 1, 8
    for row in rows[1:]:
        if row != header and len(row) > task_run and row[task_run].strip() not in ("", "N/A"):
            yield AutostartEntry("Tarea programada", row[task_name], row[task_run])


def _win_services() -> Iterator[AutostartEntry]:
    try:
        import psutil
        services = list(psutil.win_service_iter())  # type: ignore[attr-defined]
    except (ImportError, AttributeError, OSError):
        return
    for service in services:
        try:
            if service.start_type() == "automatic":
                yield AutostartEntry("Servicio", service.name(), service.binpath())
        except OSError:
            continue


# ===========================================================================
# Linux y macOS (cron, perfiles de shell, claves SSH)
# ===========================================================================
def _unix_common() -> Iterator[AutostartEntry]:
    yield from _unix_cron()
    yield from _unix_shell_profiles()
    yield from _unix_authorized_keys()
    yield from _unix_uid0_accounts()


def _unix_cron() -> Iterator[AutostartEntry]:
    files = [Path("/etc/crontab")]
    for folder in (Path("/etc/cron.d"), Path("/var/spool/cron"), Path("/var/spool/cron/crontabs")):
        files += [p for p in _glob(folder) if p.is_file()]
    for path in files:
        for line in _read(path).splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not _ENV_ASSIGNMENT.match(line):
                yield AutostartEntry("cron", str(path), line)


def _unix_shell_profiles() -> Iterator[AutostartEntry]:
    names = (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile")
    files = [Path("/etc/profile"), Path("/etc/bash.bashrc"), Path("/etc/zshrc")]
    files += _glob(Path("/etc/profile.d"), "*.sh")
    files += [home / name for home in _home_dirs() for name in names]
    for path in files:
        text = _read(path)
        if text:  # el contenido se analiza entero, pero en el informe solo aparece la ruta
            yield AutostartEntry("Perfil de shell", str(path), str(path), content=text)


def _unix_authorized_keys() -> Iterator[AutostartEntry]:
    for home in _home_dirs():
        path = home / ".ssh" / "authorized_keys"
        for line in _read(path).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            forced = line.startswith("command=")
            yield AutostartEntry("Clave SSH autorizada", str(path), line.split()[-1][:80],
                                 base_severity=Severity.MEDIUM if forced else Severity.INFO,
                                 note="la clave fuerza la ejecución de un comando" if forced else "")


def _unix_uid0_accounts() -> Iterator[AutostartEntry]:
    for line in _read(Path("/etc/passwd")).splitlines():
        fields = line.split(":")
        if len(fields) > 3 and fields[2] == "0" and fields[0] != "root":
            yield AutostartEntry("Cuenta UID 0", "/etc/passwd", fields[0], base_severity=Severity.HIGH,
                                 note=f"la cuenta «{fields[0]}» tiene privilegios de root")


def _linux() -> Iterator[AutostartEntry]:
    yield from _linux_systemd()
    rc_local = _read(Path("/etc/rc.local"))
    if rc_local.strip():
        yield AutostartEntry("rc.local", "/etc/rc.local", "/etc/rc.local", content=rc_local)
    preload = _read(Path("/etc/ld.so.preload")).strip()
    if preload:
        yield AutostartEntry("ld.so.preload", "/etc/ld.so.preload", preload, base_severity=Severity.HIGH,
                             note="biblioteca cargada en todos los procesos (técnica de rootkit)")


def _linux_systemd() -> Iterator[AutostartEntry]:
    """Solo unidades creadas por el administrador o el usuario, no las del paquete."""
    folders = [Path("/etc/systemd/system"), Path("/etc/systemd/user")]
    folders += [home / ".config" / "systemd" / "user" for home in _home_dirs()]
    for folder in folders:
        for unit in _glob(folder, "*.service"):
            if unit.is_symlink():
                continue
            text = _read(unit)
            commands = re.findall(r"^Exec(?:Start|StartPre|StartPost)=(.+)$", text, re.M)
            if commands:
                yield AutostartEntry("systemd", str(unit), commands[0].lstrip("-@+!"), content="\n".join(commands))


def _macos() -> Iterator[AutostartEntry]:
    folders = [Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]
    folders += [home / "Library" / "LaunchAgents" for home in _home_dirs()]
    for folder in folders:
        for plist in _glob(folder, "*.plist"):
            try:
                with open(plist, "rb") as handle:
                    data = plistlib.load(handle)
            except (OSError, plistlib.InvalidFileException, ValueError):
                continue
            arguments = data.get("ProgramArguments") or [data.get("Program", "")]
            if arguments and (data.get("RunAtLoad") or data.get("KeepAlive") or data.get("StartInterval")):
                yield AutostartEntry("LaunchAgent/Daemon", str(plist), " ".join(map(str, arguments)))

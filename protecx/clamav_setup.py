"""Instala y configura ClamAV desde ProtecX, usando el gestor de paquetes del propio sistema.

No se descarga ningún instalador por nuestra cuenta: winget, apt, dnf, pacman, zypper y brew
verifican las firmas de sus paquetes. Los comandos son fijos (sin shell ni datos del usuario),
se muestran antes de ejecutarse y solo se lanzan tras confirmar.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from . import config
from .signatures.clamav import ClamAV

_DOWNLOADS = "https://www.clamav.net/downloads"
_EXAMPLE = re.compile(r"^Example\s*$", re.M)   # ClamAV se niega a arrancar con esta línea sin comentar


@dataclass
class Plan:
    manager: str
    commands: list[list[str]]
    note: str                       # qué esperar (permisos, tamaño…)
    sudo: tuple[str, ...] = ()      # prefijo para freshclam después


def make_plan() -> Optional[Plan]:
    """Cómo instalar ClamAV en este equipo, o None si no hay un método automático."""
    which = shutil.which
    if config.IS_WINDOWS:
        if not which("winget"):
            return None
        return Plan("winget", [["winget", "install", "--id", "Cisco.ClamAV", "--exact",
                                "--accept-package-agreements", "--accept-source-agreements"]],
                    "Windows te pedirá permiso de administrador (ventana UAC).")
    if config.IS_MAC:
        return Plan("brew", [["brew", "install", "clamav"]], "Homebrew descarga e instala sin pedir contraseña.") \
            if which("brew") else None

    sudo: tuple[str, ...] = () if os.geteuid() == 0 else (("sudo",) if which("sudo") else ("?",))
    if sudo == ("?",):
        return None                      # ni root ni sudo: no se puede instalar de forma automática
    note = "Te pedirá tu contraseña de administrador (sudo)." if sudo else "Estás como root: no pedirá contraseña."
    if which("apt-get"):
        return Plan("apt", [[*sudo, "apt-get", "update"], [*sudo, "apt-get", "install", "-y", "clamav", "clamav-freshclam"]], note, sudo)
    if which("dnf"):
        return Plan("dnf", [[*sudo, "dnf", "install", "-y", "clamav", "clamav-update"]], note, sudo)
    if which("pacman"):
        return Plan("pacman", [[*sudo, "pacman", "-S", "--noconfirm", "clamav"]], note, sudo)
    if which("zypper"):
        return Plan("zypper", [[*sudo, "zypper", "--non-interactive", "install", "clamav"]], note, sudo)
    return None


def _comment_example(conf: Path, sudo: tuple[str, ...] = ()) -> bool:
    """Comenta la línea «Example» de un .conf. Devuelve False si no se pudo (falta de permisos)."""
    try:
        text = conf.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True                      # no existe: nada que arreglar
    if not _EXAMPLE.search(text):
        return True
    try:
        conf.write_text(_EXAMPLE.sub("#Example", text), encoding="utf-8")
        return True
    except PermissionError:
        if not sudo:
            return False
        done = subprocess.run([*sudo, "sed", "-i", "s/^Example[[:space:]]*$/#Example/", str(conf)], check=False)
        return done.returncode == 0


def _conf_dir() -> Optional[Path]:
    """Carpeta de los .conf de ClamAV, solo en las plataformas donde hay que crearlos a mano."""
    clam = ClamAV()
    if config.IS_WINDOWS and clam.scan_exe:
        return Path(clam.scan_exe).parent
    if config.IS_MAC:
        for base in (Path("/opt/homebrew/etc/clamav"), Path("/usr/local/etc/clamav")):
            if base.is_dir():
                return base
    return None


def configure(plan: Plan, log: Callable[[str], None]) -> bool:
    """Crea los .conf a partir de los ejemplos, quita «Example» y descarga las bases con freshclam."""
    conf = _conf_dir()
    try:
        if conf:
            samples = [conf / "conf_examples", conf]                       # Windows / Homebrew
            for name in ("freshclam.conf", "clamd.conf"):
                target = conf / name
                sample = next((d / f"{name}.sample" for d in samples if (d / f"{name}.sample").is_file()), None)
                if not target.exists() and sample:
                    shutil.copyfile(sample, target)
                if not _comment_example(target):
                    raise PermissionError(target)
        elif not _comment_example(Path("/etc/freshclam.conf"), plan.sudo):  # dnf/pacman/zypper dejan «Example»
            raise PermissionError("/etc/freshclam.conf")
    except PermissionError as exc:
        log(f"  Sin permisos para escribir {exc}. Abre ProtecX como administrador y repite «Instalar ClamAV».")
        return False

    log("  Descargando las bases de virus de ClamAV (freshclam, puede tardar unos minutos)…")
    ok, message = ClamAV().update(prefix=plan.sudo)
    if not ok:
        log(f"  freshclam: {message or 'falló'}")
        log("  Si dice que el archivo está bloqueado, ClamAV ya se está actualizando solo: espera unos minutos.")
    return ok


def run(ask: Callable[[str], str] = input, log: Callable[[str], None] = print) -> int:
    """Flujo completo e interactivo. Devuelve 0 si ClamAV queda listo."""
    if ClamAV().available:
        log("  ClamAV ya está instalado. Para actualizar sus bases usa la opción de actualizar firmas.")
        return 0
    plan = make_plan()
    if plan is None:
        log("  No puedo instalarlo automáticamente en este equipo (falta winget, brew, apt/dnf/pacman/zypper o sudo).")
        log(f"  Descárgalo a mano desde {_DOWNLOADS} y vuelve a abrir ProtecX.")
        return 1

    log("  Se ejecutará:")
    for command in plan.commands:
        log("    " + " ".join(command))
    log(f"  {plan.note} Ocupa unos cientos de MB entre programa y bases de virus.")
    if ask("  ¿Instalar ClamAV ahora? [s/N] ").strip().lower() not in ("s", "si", "sí", "y", "yes"):
        return 1

    for command in plan.commands:
        try:
            if subprocess.run(command, check=False, timeout=1800).returncode != 0:
                log("  La instalación falló o se canceló (mira el mensaje de arriba).")
                return 1
        except (OSError, subprocess.SubprocessError) as exc:
            log(f"  No se pudo lanzar el instalador: {exc}")
            return 1

    clam = ClamAV()
    if not clam.available:
        log("  Instalado, pero ProtecX aún no lo encuentra: cierra y vuelve a abrir esta ventana (el PATH se actualiza al abrirla).")
        return 1
    ready = configure(plan, log)
    log("  ✔ ClamAV listo: se usará en los análisis de archivos." if ready
        else "  ClamAV instalado, pero sin bases de virus todavía: repite la actualización más tarde.")
    return 0 if ready else 1

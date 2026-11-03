"""Utilidades pequeñas y sin estado: hashing, privilegios, comandos, rutas."""

from __future__ import annotations

import getpass
import hashlib
import locale
import os
import platform
import socket
import subprocess
from datetime import datetime, timezone
from typing import Any, Optional

from .config import IS_WINDOWS

_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def sha256_file(path: str, chunk: int = 1 << 20) -> Optional[str]:
    """SHA-256 de un archivo, o None si no se puede leer."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while block := handle.read(chunk):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def exec_kind(path: str) -> Optional[str]:
    """Detecta ejecutables por su cabecera ('pe', 'elf', 'macho', 'script') o None."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(4)
    except OSError:
        return None
    if head[:2] == b"MZ":
        return "pe"
    if head == b"\x7fELF":
        return "elf"
    if head in _MACHO_MAGICS:
        return "macho"
    if head[:2] == b"#!":
        return "script"
    return None


def is_admin() -> bool:
    """True si el proceso tiene privilegios de administrador/root."""
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def host_info() -> dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "os_version": platform.version(),
        "arch": platform.machine(),
        "user": getpass.getuser(),
        "admin": is_admin(),
        "python": platform.python_version(),
    }


def run_command(cmd: list[str], timeout: int = 60) -> str:
    """Ejecuta un comando (sin shell) y devuelve stdout; cadena vacía si falla."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout, check=False,
            creationflags=0x08000000 if IS_WINDOWS else 0,  # CREATE_NO_WINDOW
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.decode(locale.getpreferredencoding(False), errors="replace")


def normalize_path(path: str) -> str:
    """Minúsculas y barras '/', para comparar rutas entre sistemas."""
    return path.replace("\\", "/").lower()


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024 or unit == "GB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} GB"

"""Configuración central: detección de sistema operativo, rutas y límites."""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "protecx"
USER_AGENT = "ProtecX/0.1 (escaner defensivo)"

IS_WINDOWS = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

# Variable de entorno con la clave gratuita de abuse.ch (https://auth.abuse.ch)
AUTH_KEY_ENV = "ABUSE_CH_AUTH_KEY"
# Permite mover todos los datos (útil para pruebas o instalaciones portables)
HOME_ENV = "PROTECX_HOME"

# Límites de seguridad/rendimiento
MAX_DOWNLOAD_BYTES = 300 * 1024 * 1024   # tope por descarga de firmas
MAX_YARA_FILE_BYTES = 50 * 1024 * 1024   # no pasar YARA por archivos mayores
STALE_DB_DAYS = 7                        # aviso si las firmas son más antiguas


def data_dir() -> Path:
    """Carpeta de datos del usuario (firmas, reglas, informes), creada si falta."""
    override = os.environ.get(HOME_ENV)
    if override:
        base = Path(override)
    elif IS_WINDOWS:
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / APP_NAME
    elif IS_MAC:
        base = Path.home() / "Library" / "Application Support" / APP_NAME
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def db_path() -> Path:
    return data_dir() / "signatures.db"


def yara_rules_dir() -> Path:
    return data_dir() / "yara-rules"


def yara_cache_path() -> Path:
    return data_dir() / "yara-rules.compiled"


def app_dir() -> Path:
    """Carpeta donde viven los ejecutables: la del .exe empaquetado o la del proyecto."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def reports_dir() -> Path:
    return _writable_subdir("reports")


def quarantine_dir() -> Path:
    return _writable_subdir("quarantine")


def _writable_subdir(name: str) -> Path:
    """`<name>/` junto a los ejecutables; si no se puede escribir ahí, en la carpeta de datos."""
    for base in (app_dir(), data_dir()):
        path = base / name
        try:
            path.mkdir(parents=True, exist_ok=True)
            if os.access(path, os.W_OK):
                return path
        except OSError:
            continue
    raise OSError(f"no hay ninguna carpeta «{name}» con permiso de escritura")

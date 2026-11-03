"""Cuarentena: aísla un archivo sospechoso sin borrarlo, para poder restaurarlo si era un falso positivo.

El archivo se mueve a `quarantine/<id>.quar` (extensión neutra y, en Linux/macOS, sin permiso de
ejecución) junto a `<id>.json` con su ruta original, hash, fecha y motivo. Nada se hace por sí solo:
solo se aísla lo que el usuario pide.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from . import config
from .utils import normalize_path, sha256_file

# Carpetas del sistema: moverlas fuera puede dejar el equipo sin arrancar. Requieren force.
_PROTECTED = ("/bin/", "/sbin/", "/usr/", "/lib/", "/lib64/", "/etc/", "/boot/", "/system/", "/library/",
              "/windows/", "/program files/", "/program files (x86)/")


class QuarantineError(Exception):
    """Fallo esperable (ruta inválida, archivo en uso...) con un mensaje listo para el usuario."""


@dataclass
class Item:
    id: str
    original: str
    sha256: str
    size: int
    mode: int
    quarantined_at: str
    reason: str = ""


def protected_reason(path: Path) -> Optional[str]:
    norm = normalize_path(str(path.resolve()))
    norm = norm.split(":", 1)[-1]          # 'c:/windows/…' -> '/windows/…'
    if any(norm.startswith(prefix) for prefix in _PROTECTED):
        return "está en una carpeta del sistema o de programas instalados"
    own = normalize_path(str(config.app_dir() / "protecx")) + "/"
    if normalize_path(str(path.resolve())).startswith(own):
        return "es parte de ProtecX"
    return None


def _meta_path(item_id: str) -> Path:
    return config.quarantine_dir() / f"{item_id}.json"


def _blob_path(item_id: str) -> Path:
    return config.quarantine_dir() / f"{item_id}.quar"


def add(path: str, reason: str = "", force: bool = False) -> Item:
    source = Path(path).expanduser()
    if source.is_symlink() or not source.is_file():
        raise QuarantineError(f"«{path}» no es un archivo normal (o ya no existe).")
    if not force and (why := protected_reason(source)):
        raise QuarantineError(f"No se aísla «{path}»: {why}. Si estás seguro, usa --force.")
    digest = sha256_file(str(source))
    if digest is None:
        raise QuarantineError(f"No se puede leer «{path}» (¿permisos?).")

    info = source.stat()
    item = Item(f"{datetime.now():%Y%m%d-%H%M%S}-{digest[:8]}", str(source.resolve()), digest, info.st_size,
                stat.S_IMODE(info.st_mode), datetime.now().astimezone().isoformat(timespec="seconds"), reason)
    meta = _meta_path(item.id)
    meta.write_text(json.dumps(asdict(item), ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        shutil.move(str(source), _blob_path(item.id))
    except PermissionError as exc:
        meta.unlink(missing_ok=True)
        raise QuarantineError(f"«{path}» está en uso o protegido. Cierra el programa que lo usa e inténtalo de nuevo.") from exc
    except OSError as exc:
        meta.unlink(missing_ok=True)
        raise QuarantineError(f"No se pudo mover «{path}»: {exc}") from exc
    if os.name == "posix":
        _blob_path(item.id).chmod(0o600)   # sin bit de ejecución
    return item


def list_items() -> list[Item]:
    items = []
    for meta in sorted(config.quarantine_dir().glob("*.json")):
        try:
            items.append(Item(**json.loads(meta.read_text(encoding="utf-8"))))
        except (OSError, ValueError, TypeError):
            continue   # metadatos corruptos: se ignoran, el archivo sigue guardado
    return items


def _find(item_id: str) -> Item:
    matches = [i for i in list_items() if i.id == item_id or i.id.startswith(item_id)]
    if len(matches) != 1:
        raise QuarantineError(f"No hay un elemento único con id «{item_id}» (mira `quarantine list`).")
    return matches[0]


def restore(item_id: str, force: bool = False) -> Path:
    item = _find(item_id)
    target = Path(item.original)
    if target.exists() and not force:
        raise QuarantineError(f"Ya existe «{target}». Usa --force para sobrescribirlo.")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(_blob_path(item.id)), target)
        if os.name == "posix":
            target.chmod(item.mode)        # devuelve los permisos originales
        _meta_path(item.id).unlink(missing_ok=True)
    except OSError as exc:
        raise QuarantineError(f"No se pudo restaurar en «{target}»: {exc}") from exc
    return target


def delete(item_id: str) -> Item:
    item = _find(item_id)
    try:
        _blob_path(item.id).unlink(missing_ok=True)
        _meta_path(item.id).unlink(missing_ok=True)
    except OSError as exc:
        raise QuarantineError(f"No se pudo eliminar {item.id}: {exc}") from exc
    return item

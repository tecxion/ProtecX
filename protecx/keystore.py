"""Guarda la clave de abuse.ch en un archivo cifrado para escribirla solo la primera vez.

- Windows: DPAPI (la misma protección que usa Chrome para sus contraseñas). Solo tu cuenta de Windows,
  en este equipo, puede descifrarla; copiar el archivo a otro equipo o usuario no sirve.
- Linux/macOS: no hay un equivalente universal sin instalar nada, así que se guarda codificada en base64
  con permisos 0600 (solo tu usuario). Eso evita verla de pasada, pero NO es cifrado fuerte:
  shortcut: base64 + 0600, cambiar a Keychain/libsecret si se quiere cifrado real en esas plataformas.
"""

from __future__ import annotations

import base64
import os
import re
from pathlib import Path
from typing import Optional

from . import config

# La clave va dentro de la URL de descarga: se rechaza cualquier carácter que pueda alterar la ruta.
_VALID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_TAG_DPAPI, _TAG_PLAIN = b"DPAPI1\n", b"B64-0600\n"


def is_valid(key: str) -> bool:
    return bool(_VALID.match(key or ""))


def path() -> Path:
    return config.data_dir() / "abuse_ch.key"


def _dpapi(protect: bool, data: bytes) -> bytes:
    """CryptProtectData / CryptUnprotectData de Windows, solo con ctypes (sin dependencias)."""
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buffer = ctypes.create_string_buffer(data, len(data))
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    result = Blob()
    function = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData  # type: ignore[attr-defined]
    if not function(ctypes.byref(source), None, None, None, None, 0, ctypes.byref(result)):
        raise OSError("DPAPI no pudo procesar la clave")
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(result.pbData, ctypes.c_void_p))  # type: ignore[attr-defined]


def method() -> str:
    return "cifrada con tu cuenta de Windows" if config.IS_WINDOWS else "archivo privado, solo tu usuario"


def save(key: str) -> str:
    """Guarda la clave y devuelve cómo (para decírselo al usuario)."""
    if not is_valid(key):
        raise ValueError("clave con formato no válido")
    blob = _TAG_DPAPI + _dpapi(True, key.encode()) if config.IS_WINDOWS else _TAG_PLAIN + base64.b64encode(key.encode())
    target = path()
    temp = target.with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # nace privado, sin ventana de lectura
    with os.fdopen(fd, "wb") as handle:
        handle.write(blob)
    os.replace(temp, target)
    return method()


def load() -> Optional[str]:
    """La clave guardada, o None si no hay, no se puede descifrar (otro usuario/equipo) o es inválida."""
    try:
        blob = path().read_bytes()
        if blob.startswith(_TAG_DPAPI) and config.IS_WINDOWS:
            key = _dpapi(False, blob[len(_TAG_DPAPI):]).decode()
        elif blob.startswith(_TAG_PLAIN) and not config.IS_WINDOWS:
            key = base64.b64decode(blob[len(_TAG_PLAIN):]).decode()
        else:
            return None
    except (OSError, ValueError):
        return None
    return key if is_valid(key) else None


def forget() -> bool:
    try:
        path().unlink()
        return True
    except OSError:
        return False

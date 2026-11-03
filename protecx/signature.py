"""Firma digital de ejecutables (Authenticode, solo Windows).

Una firma válida de un editor conocido es una buena señal para descartar falsos positivos
(un instalador legítimo en Descargas); una firma rota indica que el archivo se modificó
después de firmarse. En Linux/macOS no hay equivalente universal: `check` devuelve {}.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Iterable

from .config import IS_WINDOWS

_BATCH = 200       # rutas por llamada a PowerShell (cada arranque cuesta ~1 s)
_TIMEOUT = 180

# Las rutas viajan por stdin en JSON con \uXXXX (ASCII puro): sin problemas de codificación ni de longitud.
_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$paths = @([Console]::In.ReadToEnd() | ConvertFrom-Json)
$i = 0
$out = foreach ($p in $paths) {
  $s = Get-AuthenticodeSignature -LiteralPath $p
  [pscustomobject]@{ i = $i; status = [string]$s.Status; subject = [string]$s.SignerCertificate.Subject }
  $i++
}
ConvertTo-Json -Compress -InputObject @($out)
"""


@dataclass(frozen=True)
class Signature:
    status: str       # Valid, NotSigned, HashMismatch, NotTrusted, UnknownError...
    publisher: str    # nombre del firmante ('' si no hay)

    @property
    def valid(self) -> bool:
        return self.status == "Valid"

    @property
    def tampered(self) -> bool:
        return self.status == "HashMismatch"   # firmado, pero el contenido cambió después

    def describe(self) -> str:
        if self.valid:
            return f"Firmado por {self.publisher or 'un editor desconocido'} (firma válida)"
        if self.status == "NotSigned":
            return "Sin firma digital"
        if self.tampered:
            return f"FIRMA ROTA: el archivo se modificó después de firmarse ({self.publisher})"
        return f"Firma no válida o no confiable ({self.status})"


def publisher_name(subject: str) -> str:
    """'CN="Microsoft Corporation", O=...' -> 'Microsoft Corporation'."""
    match = re.search(r'CN=("(?:[^"]|"")*"|[^,]+)', subject or "")
    return match.group(1).strip().strip('"').replace('""', '"') if match else ""


def parse(output: str, paths: list[str]) -> dict[str, Signature]:
    """Salida JSON de PowerShell -> firma por ruta (se empareja por posición)."""
    try:
        rows = json.loads(output)
    except ValueError:
        return {}
    if isinstance(rows, dict):       # PowerShell no devuelve lista si solo hay un elemento
        rows = [rows]
    result = {}
    for row in rows:
        index = row.get("i")
        if isinstance(index, int) and 0 <= index < len(paths) and row.get("status"):
            result[paths[index]] = Signature(row["status"], publisher_name(row.get("subject", "")))
    return result


def check(paths: Iterable[str]) -> dict[str, Signature]:
    """Firma de cada ruta. Vacío si no es Windows o PowerShell no responde (nunca lanza)."""
    unique = sorted(set(paths))
    if not IS_WINDOWS or not unique:
        return {}
    found: dict[str, Signature] = {}
    for start in range(0, len(unique), _BATCH):
        chunk = unique[start:start + _BATCH]
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", _SCRIPT],
                input=json.dumps(chunk).encode("ascii"), capture_output=True, timeout=_TIMEOUT, check=False)
            found.update(parse(proc.stdout.decode("utf-8", errors="replace"), chunk))
        except (OSError, subprocess.SubprocessError):
            continue
    return found

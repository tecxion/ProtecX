"""Descarga y actualiza las bases de firmas desde fuentes públicas.

Fuentes (todas gratuitas):
  - abuse.ch: MalwareBazaar (hashes), ThreatFox (IOCs), URLhaus (hosts de
    distribución). Desde 2026 las URLs antiguas sin clave devuelven HTTP 410:
    las exportaciones v2 exigen una clave gratuita (https://auth.abuse.ch)
    que va en la ruta de la URL.
  - Feodo Tracker: IPs de servidores C2 de botnets.
  - Neo23x0/signature-base: reglas YARA (licencia DRL 1.1, cita al autor).

ClamAV NO se descarga aquí: su proyecto pide usar `freshclam` (ver clamav.py).
Una fuente que falla no borra los datos que ya había de ella.
"""

from __future__ import annotations

import io
import shutil
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

from .. import config
from . import parsers
from .store import SignatureStore

Log = Callable[[str], None]

YARA_ZIP_URL = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"

# Reglas que dependen de variables externas de LOKI/THOR o dan muchos falsos positivos
YARA_EXCLUDED = {
    "generic_anomalies.yar", "general_cloaking.yar", "gen_webshells_ext_vars.yar",
    "thor_inverse_matches.yar", "yara_mixed_ext_vars.yar", "configured_vulns_ext_vars.yar",
    "gen_fake_amsi_dll.yar", "expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar",
    "yara-rules_vuln_drivers_strict_renamed.yar",
}


@dataclass(frozen=True)
class Feed:
    name: str
    url: str                      # '{key}' se sustituye por la clave de abuse.ch
    parse: Callable[[str], parsers.ParsedFeed]
    zipped: bool = False
    key_in_url: bool = True       # las exportaciones v2 de abuse.ch llevan la clave en la ruta


FEEDS = (
    Feed("malwarebazaar", "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv",
         parsers.parse_malwarebazaar_csv),
    Feed("threatfox", "https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip",
         parsers.parse_threatfox_csv, zipped=True, key_in_url=True),
    Feed("urlhaus", "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv",
         parsers.parse_urlhaus_csv),
    Feed("feodotracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
         parsers.parse_ip_list, key_in_url=False),
)


@dataclass
class UpdateResult:
    name: str
    ok: bool
    count: int = 0
    message: str = ""


# ---------------------------------------------------------------------------
# Descarga
# ---------------------------------------------------------------------------
def _fetch(url: str, auth_key: Optional[str], timeout: int = 90) -> bytes:
    """GET con tope de tamaño. La clave solo se envía a hosts de abuse.ch."""
    headers = {"User-Agent": config.USER_AGENT}
    host = urlparse(url).hostname or ""
    if auth_key and (host == "abuse.ch" or host.endswith(".abuse.ch")):
        headers["Auth-Key"] = auth_key
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(config.MAX_DOWNLOAD_BYTES + 1)
    if len(data) > config.MAX_DOWNLOAD_BYTES:
        raise ValueError("la descarga supera el tamaño máximo permitido")
    return data


def _explain(exc: Exception, needs_key: bool = False) -> str:
    """Mensaje de error legible (sin exponer URLs que puedan contener la clave)."""
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in (401, 403) and needs_key:
            return (f"acceso denegado (HTTP {exc.code}): define la clave gratuita de "
                    f"abuse.ch en {config.AUTH_KEY_ENV} o con --auth-key")
        return f"HTTP {exc.code}"
    if isinstance(exc, urllib.error.URLError):
        return f"sin conexión ({exc.reason})"
    return str(exc) or exc.__class__.__name__


def _unzip_first_member(data: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        member = archive.infolist()[0]
        if member.file_size > config.MAX_DOWNLOAD_BYTES * 2:
            raise ValueError("el archivo descomprimido es demasiado grande")
        return archive.read(member).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Actualización de hashes e IOCs
# ---------------------------------------------------------------------------
def update_feeds(store: SignatureStore, auth_key: Optional[str], log: Log = print) -> list[UpdateResult]:
    results = []
    for feed in FEEDS:
        if feed.key_in_url and not auth_key:
            results.append(UpdateResult(feed.name, False, message=f"requiere clave ({config.AUTH_KEY_ENV})"))
            continue
        try:
            log(f"  descargando {feed.name}…")
            raw = _fetch(feed.url.format(key=auth_key or ""), auth_key)
            text = _unzip_first_member(raw) if feed.zipped else raw.decode("utf-8", errors="replace")
            parsed = feed.parse(text)
            if not len(parsed):  # no machacar datos buenos con una respuesta vacía/errónea
                raise ValueError("la respuesta no contiene datos reconocibles")
            count = store.replace_source(feed.name, parsed.hashes, parsed.iocs)
            results.append(UpdateResult(feed.name, True, count))
        except Exception as exc:  # noqa: BLE001 - una fuente caída no debe frenar las demás
            results.append(UpdateResult(feed.name, False, message=_explain(exc, needs_key=True)))
    return results


# ---------------------------------------------------------------------------
# Actualización de reglas YARA
# ---------------------------------------------------------------------------
def update_yara_rules(rules_dir: Optional[Path] = None, log: Log = print) -> UpdateResult:
    """Descarga signature-base y sustituye de forma atómica la carpeta de reglas."""
    rules_dir = rules_dir or config.yara_rules_dir()
    staging = rules_dir.with_name(rules_dir.name + ".new")
    try:
        log("  descargando reglas YARA (signature-base)…")
        data = _fetch(YARA_ZIP_URL, None, timeout=180)
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True)
        written = _extract_yara(data, staging)
        if not written:
            raise ValueError("el paquete no contiene reglas .yar")
        shutil.rmtree(rules_dir, ignore_errors=True)
        staging.rename(rules_dir)
        config.yara_cache_path().unlink(missing_ok=True)  # forzar recompilación
        return UpdateResult("yara-signature-base", True, written)
    except Exception as exc:  # noqa: BLE001
        shutil.rmtree(staging, ignore_errors=True)
        return UpdateResult("yara-signature-base", False, message=_explain(exc))


def _extract_yara(data: bytes, target: Path) -> int:
    """Extrae solo los .yar de la carpeta yara/, usando únicamente el nombre base
    (evita rutas maliciosas tipo '../') y descartando las reglas excluidas."""
    written = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.infolist():
            parts = member.filename.split("/")
            name = parts[-1]
            if member.is_dir() or "yara" not in parts[:-1] or not name.lower().endswith((".yar", ".yara")):
                continue
            if name in YARA_EXCLUDED or member.file_size > 20 * 1024 * 1024:
                continue
            (target / name).write_bytes(archive.read(member))
            written += 1
    return written

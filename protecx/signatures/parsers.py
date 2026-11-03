"""Convierte los formatos de cada feed público en hashes e IOCs normalizados."""

from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_TF_DEFAULT_COLUMNS = (
    "first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type",
    "fk_malware", "malware_alias", "malware_printable",
)
_MB_DEFAULT_COLUMNS = (
    "first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash", "reporter", "file_name",
    "file_type_guess", "mime_type", "signature", "clamav", "vtpercent", "imphash",
    "ssdeep", "tlsh",
)
_UH_DEFAULT_COLUMNS = (
    "id", "dateadded", "url", "url_status", "last_online", "threat", "tags",
    "urlhaus_link", "reporter",
)


@dataclass
class ParsedFeed:
    hashes: list[tuple[str, str]] = field(default_factory=list)       # (sha256, familia)
    iocs: list[tuple[str, str, str]] = field(default_factory=list)    # (tipo, valor, familia)

    def __len__(self) -> int:
        return len(self.hashes) + len(self.iocs)


def _data_lines(text: str):
    """Líneas útiles de un feed de texto (sin comentarios ni vacías)."""
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield line


def _host_kind(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "domain"


def _is_ip(value: str) -> bool:
    return _host_kind(value) == "ip"


def parse_ip_list(text: str, family: str = "botnet-c2") -> ParsedFeed:
    """Una IP por línea (Feodo Tracker y similares)."""
    parsed = ParsedFeed()
    parsed.iocs = [("ip", line, family) for line in _data_lines(text) if _is_ip(line)]
    return parsed


def _csv_table(text: str, marker: str, default_columns: tuple[str, ...]):
    """Lee un CSV de abuse.ch: la cabecera viene en un comentario ('# col1,col2…').

    Devuelve (índice nombre→posición, filas). Si no hay cabecera se usan las columnas
    por defecto del feed.
    """
    columns = None
    rows: list[list[str]] = []
    for line in text.splitlines():
        if line.startswith("#"):
            if marker in line:
                columns = next(csv.reader([line.lstrip("# ").strip()], skipinitialspace=True))
        elif line.strip():
            rows.extend(csv.reader([line], skipinitialspace=True))
    return {name: i for i, name in enumerate(columns or default_columns)}, rows


def _cell(rec: list[str], index: dict[str, int], name: str, default: str = "") -> str:
    i = index.get(name)
    return rec[i].strip() if i is not None and i < len(rec) else default


def parse_malwarebazaar_csv(text: str) -> ParsedFeed:
    """recent.csv de MalwareBazaar (últimas 48 h): SHA-256 + firma/familia."""
    index, rows = _csv_table(text, "sha256_hash", _MB_DEFAULT_COLUMNS)
    parsed = ParsedFeed()
    for rec in rows:
        sha = _cell(rec, index, "sha256_hash")
        if _SHA256.match(sha):
            family = _cell(rec, index, "signature")
            parsed.hashes.append((sha.lower(), family if family.lower() not in ("", "n/a", "none") else "malware"))
    return parsed


def parse_urlhaus_csv(text: str, family: str = "malware-distribution") -> ParsedFeed:
    """recent.csv de URLhaus: se guarda el host (IP o dominio) de las URLs en línea."""
    index, rows = _csv_table(text, "url_status", _UH_DEFAULT_COLUMNS)
    parsed = ParsedFeed()
    seen: set[tuple[str, str]] = set()
    for rec in rows:
        if _cell(rec, index, "url_status", "online") != "online":
            continue
        host = urlparse(_cell(rec, index, "url")).hostname
        if host and (key := (_host_kind(host), host.lower())) not in seen:
            seen.add(key)
            parsed.iocs.append((key[0], key[1], _cell(rec, index, "threat", family) or family))
    return parsed


def parse_threatfox_csv(text: str) -> ParsedFeed:
    """CSV de ThreatFox (hashes, IPs, dominios y URLs)."""
    index, rows = _csv_table(text, "ioc_value", _TF_DEFAULT_COLUMNS)
    parsed = ParsedFeed()
    if "ioc_value" not in index or "ioc_type" not in index:
        return parsed
    family_col = "malware_printable" if "malware_printable" in index else "fk_malware"
    for rec in rows:
        value, kind = _cell(rec, index, "ioc_value"), _cell(rec, index, "ioc_type")
        family = _cell(rec, index, family_col, "threatfox")
        if kind == "sha256_hash" and _SHA256.match(value):
            parsed.hashes.append((value.lower(), family))
        elif kind == "ip:port":
            parsed.iocs.append(("ip", value.rsplit(":", 1)[0], family))
        elif kind == "domain":
            parsed.iocs.append(("domain", value.lower(), family))
        elif kind == "url" and (host := urlparse(value).hostname):
            parsed.iocs.append((_host_kind(host), host.lower(), family))
    return parsed

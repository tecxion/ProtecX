"""Almacén SQLite de hashes de malware e IOCs de red (IPs y dominios).

Una sola conexión compartida entre hilos, protegida con un lock: las
búsquedas son por clave primaria y tardan microsegundos.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from .. import config

# SHA-256 del fichero de prueba EICAR (inofensivo, estándar para probar antivirus)
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
BUILTIN_SOURCE = "builtin"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hashes (
    sha256 TEXT PRIMARY KEY, family TEXT, source TEXT
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS iocs (
    kind TEXT, value TEXT, family TEXT, source TEXT,
    PRIMARY KEY (kind, value)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX IF NOT EXISTS idx_hashes_source ON hashes(source);
CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);
"""


class SignatureStore:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else config.db_path()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._db:
            self._db.executescript(_SCHEMA)
            self._db.execute(
                "INSERT OR IGNORE INTO hashes VALUES (?, ?, ?)",
                (EICAR_SHA256, "EICAR-Test-File", BUILTIN_SOURCE),
            )

    # -- consultas ---------------------------------------------------------
    def lookup_hash(self, sha256: str) -> Optional[tuple[str, str]]:
        """(familia, fuente) si el hash es malware conocido."""
        with self._lock:
            row = self._db.execute(
                "SELECT family, source FROM hashes WHERE sha256 = ?", (sha256.lower(),)
            ).fetchone()
        return (row[0], row[1]) if row else None

    def lookup_ioc(self, kind: str, value: str) -> Optional[tuple[str, str]]:
        """(familia, fuente) si la IP/dominio figura como malicioso."""
        with self._lock:
            row = self._db.execute(
                "SELECT family, source FROM iocs WHERE kind = ? AND value = ?",
                (kind, value.lower()),
            ).fetchone()
        return (row[0], row[1]) if row else None

    # -- escritura ---------------------------------------------------------
    def replace_source(
        self,
        source: str,
        hashes: Iterable[tuple[str, str]] = (),
        iocs: Iterable[tuple[str, str, str]] = (),
    ) -> int:
        """Sustituye todo lo que aportó una fuente (así caducan los IOCs viejos)."""
        hashes, iocs = list(hashes), list(iocs)
        with self._lock, self._db:  # una transacción: o entra todo o nada
            self._db.execute("DELETE FROM hashes WHERE source = ?", (source,))
            self._db.execute("DELETE FROM iocs WHERE source = ?", (source,))
            self._db.executemany(
                "INSERT OR REPLACE INTO hashes VALUES (?, ?, ?)",
                ((h.lower(), fam, source) for h, fam in hashes),
            )
            self._db.executemany(
                "INSERT OR REPLACE INTO iocs VALUES (?, ?, ?, ?)",
                ((kind, value.lower(), fam, source) for kind, value, fam in iocs),
            )
            self._set_meta(f"updated:{source}", datetime.now(timezone.utc).isoformat(timespec="seconds"))
            self._set_meta("last_update", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        return len(hashes) + len(iocs)

    def _set_meta(self, key: str, value: str) -> None:
        self._db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))

    # -- información -------------------------------------------------------
    def info(self) -> dict[str, Any]:
        with self._lock:
            hashes = self._db.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
            iocs = self._db.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            meta = dict(self._db.execute("SELECT key, value FROM meta").fetchall())
        return {
            "hashes": hashes,
            "iocs": iocs,
            "last_update": meta.get("last_update"),
            "sources": {k.split(":", 1)[1]: v for k, v in meta.items() if k.startswith("updated:")},
        }

    def close(self) -> None:
        with self._lock:
            self._db.close()

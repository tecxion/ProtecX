"""Inspección de un archivo concreto (hash + YARA), compartida por varios escáneres.

Procesos, persistencia y archivos necesitan comprobar "¿este binario es malware
conocido?". Centralizarlo evita duplicar lógica y permite cachear resultados:
el mismo ejecutable suele aparecer como proceso, servicio y archivo.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from ..models import Finding, Severity
from ..utils import sha256_file

if TYPE_CHECKING:
    from ..signatures import SignatureStore, YaraEngine
    from ..signatures.yara_engine import YaraHit


@dataclass(frozen=True)
class Inspection:
    path: str
    sha256: Optional[str]
    family: Optional[str]
    source: Optional[str]
    yara_hits: tuple["YaraHit", ...]

    def findings(self, scanner: str, context: str = "") -> list[Finding]:
        """Convierte el resultado en hallazgos. `context` aclara quién usa el archivo."""
        where = f" ({context})" if context else ""
        found = []
        if self.family:
            found.append(Finding(
                scanner, Severity.CRITICAL,
                f"Malware conocido: {self.family}{where}",
                "El hash SHA-256 coincide con una muestra catalogada.",
                {"ruta": self.path, "sha256": self.sha256, "familia": self.family, "fuente": self.source},
                "Aísla el equipo de la red, conserva el archivo para análisis y elimínalo "
                "desde un entorno de confianza.",
            ))
        for hit in self.yara_hits:
            found.append(Finding(
                scanner, hit.severity,
                f"Regla YARA «{hit.rule}»{where}",
                hit.description or "El contenido coincide con una regla de detección.",
                {"ruta": self.path, "sha256": self.sha256, "regla": hit.rule, "puntuacion": hit.score},
                "Revisa el archivo con un segundo motor (por ejemplo VirusTotal). "
                "Las reglas genéricas pueden dar falsos positivos.",
            ))
        return found


class FileInspector:
    def __init__(self, store: "SignatureStore", yara_engine: "YaraEngine"):
        self._store = store
        self._yara = yara_engine
        self._cache: dict[str, Inspection] = {}

    def inspect(self, path: str, use_yara: bool = True) -> Inspection:
        cached = self._cache.get(path)
        if cached:
            return cached
        sha = sha256_file(path)
        match = self._store.lookup_hash(sha) if sha else None
        hits = tuple(self._yara.scan_file(path)) if use_yara and sha else ()
        result = Inspection(path, sha, match[0] if match else None, match[1] if match else None, hits)
        self._cache[path] = result
        return result

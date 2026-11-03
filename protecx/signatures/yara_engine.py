"""Motor YARA: compila (con caché) las reglas y analiza archivos o memoria.

yara-python es opcional: si no está instalado, `available` es False y el resto
de la herramienta sigue funcionando con hashes e IOCs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .. import config
from ..models import Severity

try:
    import yara  # type: ignore
except ImportError:  # pragma: no cover - depende del entorno
    yara = None

BUILTIN_DIR = Path(__file__).resolve().parent.parent / "rules"

# Variables externas que usan muchas reglas de signature-base (formato LOKI/THOR)
_EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}


@dataclass(frozen=True)
class YaraHit:
    rule: str
    description: str
    score: int

    @property
    def severity(self) -> Severity:
        if self.score >= 90:
            return Severity.CRITICAL
        return Severity.HIGH if self.score >= 70 else Severity.MEDIUM


class YaraEngine:
    def __init__(self, rules_dir: Optional[Path] = None, cache_path: Optional[Path] = None):
        self.rules_dir = rules_dir or config.yara_rules_dir()
        self.cache_path = cache_path or config.yara_cache_path()
        self.warnings: list[str] = []
        self.rule_files = 0
        self._rules = None

    @property
    def available(self) -> bool:
        return yara is not None

    @property
    def loaded(self) -> bool:
        return self._rules is not None

    # -- carga -------------------------------------------------------------
    def load(self) -> bool:
        """Carga las reglas (desde caché si está al día). False si no hay YARA."""
        if not self.available:
            return False
        sources = self._rule_files()
        if self._cache_is_fresh(sources):
            try:
                self._rules = yara.load(str(self.cache_path))
                self.rule_files = len(sources)
                return True
            except yara.Error:
                pass  # caché corrupta o de otra versión: recompilar
        return self._compile(sources)

    def _rule_files(self) -> list[Path]:
        files = sorted(BUILTIN_DIR.glob("*.yar"))
        if self.rules_dir.is_dir():
            files += sorted(self.rules_dir.glob("*.yar")) + sorted(self.rules_dir.glob("*.yara"))
        return files

    def _cache_is_fresh(self, sources: list[Path]) -> bool:
        if not self.cache_path.exists():
            return False
        cache_time = self.cache_path.stat().st_mtime
        return all(src.stat().st_mtime <= cache_time for src in sources)

    def _compile(self, sources: list[Path]) -> bool:
        """Valida cada archivo por separado: una regla rota no tumba al resto."""
        valid: dict[str, str] = {}
        for src in sources:
            try:
                yara.compile(filepath=str(src), externals=_EXTERNALS)
            except yara.Error as exc:
                self.warnings.append(f"regla YARA descartada ({src.name}): {exc}")
                continue
            # El espacio de nombres evita choques si dos archivos repiten un nombre de regla
            valid[f"{src.parent.name}_{src.stem}"] = str(src)
        if not valid:
            return False
        self._rules = yara.compile(filepaths=valid, externals=_EXTERNALS)
        self.rule_files = len(valid)
        try:
            self._rules.save(str(self.cache_path))
        except yara.Error:
            pass  # sin caché solo se pierde velocidad en la próxima ejecución
        return True

    # -- análisis ----------------------------------------------------------
    def scan_file(self, path: str, timeout: int = 30) -> list[YaraHit]:
        if not self.loaded:
            return []
        try:
            if os.path.getsize(path) > config.MAX_YARA_FILE_BYTES:
                return []
            directory, name = os.path.split(path)
            externals = {
                "filename": name, "filepath": directory,
                "extension": os.path.splitext(name)[1].lower(), "filetype": "", "owner": "",
            }
            matches = self._rules.match(filepath=path, timeout=timeout, externals=externals)
        except (yara.Error, OSError):
            return []  # archivo bloqueado, desaparecido o tiempo agotado
        return [self._to_hit(m) for m in matches]

    def scan_pid(self, pid: int, timeout: int = 60) -> list[YaraHit]:
        """Analiza la memoria de un proceso (requiere privilegios)."""
        if not self.loaded:
            return []
        try:
            matches = self._rules.match(pid=pid, timeout=timeout)
        except (yara.Error, OSError):
            return []
        return [self._to_hit(m) for m in matches]

    @staticmethod
    def _to_hit(match) -> YaraHit:
        meta = match.meta or {}
        try:
            score = int(meta.get("score", 60))
        except (TypeError, ValueError):
            score = 60
        return YaraHit(match.rule, str(meta.get("description", "")), score)

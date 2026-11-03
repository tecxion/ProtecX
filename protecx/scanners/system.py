"""Integridad del sistema: archivo hosts y desactivación de protecciones."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from .. import heuristics
from ..config import IS_WINDOWS
from ..models import Finding, Severity
from .base import Scanner

_SECURITY_DOMAINS = heuristics.SECURITY_DOMAINS  # tupla: sirve directamente con endswith()


class SystemScanner(Scanner):
    name = "system"
    label = "Sistema"

    def run(self) -> Iterator[Finding]:
        yield from self._hosts_file()
        if IS_WINDOWS:
            yield from self._defender_policy()

    def _hosts_file(self) -> Iterator[Finding]:
        """Dos señales: dominios maliciosos conocidos y dominios de seguridad
        redirigidos (el malware los bloquea para impedir actualizaciones)."""
        path = Path(r"C:\Windows\System32\drivers\etc\hosts") if IS_WINDOWS else Path("/etc/hosts")
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError as exc:
            self.warn(f"no se pudo leer {path}: {exc}")
            return

        for raw in lines:
            parts = raw.split("#", 1)[0].split()
            if len(parts) < 2:
                continue
            address, hostnames = parts[0], [h.lower() for h in parts[1:]]
            evidence = {"linea": raw.strip(), "archivo": str(path)}
            for host in hostnames:
                known = self.ctx.store.lookup_ioc("domain", host)
                if known:
                    yield self.finding(
                        Severity.HIGH, f"El archivo hosts apunta a un dominio malicioso: {host}",
                        f"Figura en {known[1]} asociado a «{known[0]}».",
                        "Elimina la línea y revisa cómo llegó ahí.", **evidence)
                if host.endswith(_SECURITY_DOMAINS):
                    yield self.finding(
                        Severity.HIGH, f"El archivo hosts redirige un dominio de seguridad: {host}",
                        f"Apunta a {address}. El malware lo hace para bloquear actualizaciones o análisis.",
                        "Elimina la línea del archivo hosts.", **evidence)

    def _defender_policy(self) -> Iterator[Finding]:
        """Windows: directivas que desactivan Microsoft Defender."""
        try:
            import winreg  # type: ignore
        except ImportError:
            return
        keys = (
            (r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"),
        )
        for subkey, value in keys:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as key:
                    data, _ = winreg.QueryValueEx(key, value)
            except OSError:
                continue
            if data == 1:
                yield self.finding(
                    Severity.HIGH, "Microsoft Defender desactivado por directiva",
                    f"{value}=1 en HKLM\\{subkey}.",
                    "Si no lo configuraste tú, el malware puede haberlo desactivado.",
                    clave=f"HKLM\\{subkey}", valor=value)

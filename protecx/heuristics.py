"""Reglas heurísticas compartidas por los escáneres.

Todo el conocimiento "estático" (patrones de comandos, rutas sospechosas,
puertos típicos de backdoors...) vive aquí para no duplicarlo entre módulos.
Son indicios, no pruebas: cada regla indica su gravedad y el motivo.
"""

from __future__ import annotations

import os
import re
from typing import Optional

from .models import Severity
from .utils import normalize_path

S = Severity
_L = r"[^\n]*"  # "resto de la línea": evita regex con retroceso catastrófico

# ---------------------------------------------------------------------------
# Líneas de comandos sospechosas (procesos, tareas programadas, cron, perfiles)
# ---------------------------------------------------------------------------
_COMMAND_RULES = (
    (rf"powershell{_L}\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{{20,}}", S.HIGH,
     "PowerShell con comando codificado en Base64"),
    (rf"powershell{_L}(downloadstring|downloadfile|invoke-webrequest|\biwr\b|\biex\b|invoke-expression|net\.webclient)",
     S.HIGH, "PowerShell que descarga o ejecuta contenido remoto"),
    (rf"powershell{_L}-w(indowstyle)?\s+hidden", S.MEDIUM, "PowerShell con ventana oculta"),
    (rf"(ba|z)?sh\s+-i{_L}/dev/tcp/", S.CRITICAL, "Reverse shell de bash (/dev/tcp)"),
    (r"/dev/tcp/\d", S.HIGH, "Redirección a /dev/tcp (típica de reverse shell)"),
    (rf"\b(nc|ncat|netcat)\b{_L}\s-(e|c)\s", S.CRITICAL, "Netcat ejecutando una shell remota"),
    (rf"(curl|wget)\b{_L}\|\s*(sudo\s+)?(ba|z)?sh\b", S.HIGH, "Descarga y ejecución directa de un script"),
    (rf"base64\s+(-d|--decode){_L}\|\s*(ba|z)?sh\b", S.HIGH, "Carga útil Base64 enviada a una shell"),
    (r"mshta(\.exe)?\s+[\"']?(https?:|javascript:|vbscript:)", S.HIGH, "mshta ejecutando contenido remoto/script"),
    (rf"certutil{_L}-urlcache", S.HIGH, "certutil usado para descargar archivos"),
    (rf"bitsadmin{_L}/transfer", S.MEDIUM, "bitsadmin descargando archivos"),
    (rf"regsvr32{_L}/i:https?://", S.HIGH, "regsvr32 cargando un script remoto"),
    (rf"rundll32{_L}(javascript:|vbscript:)", S.HIGH, "rundll32 ejecutando script"),
    (rf"python[0-9.]*\s+-c\s{_L}socket{_L}(subprocess|pty|dup2)", S.HIGH, "Reverse shell en Python"),
    (rf"perl\s+-e\s{_L}socket", S.HIGH, "Reverse shell en Perl"),
    (r"stratum\+tcp://|\bxmrig\b|\bminerd\b", S.HIGH, "Minero de criptomonedas"),
    (rf"vssadmin{_L}delete\s+shadows|wmic{_L}shadowcopy{_L}delete", S.CRITICAL,
     "Borrado de copias de seguridad (típico de ransomware)"),
    (rf"bcdedit{_L}recoveryenabled\s+no", S.HIGH, "Desactivación de la recuperación de Windows"),
    (r"chmod\s+\+x\s+/(tmp|dev/shm|var/tmp)/", S.MEDIUM, "Permisos de ejecución en carpeta temporal"),
    (rf"(wget|curl)\b{_L}\s-[A-Za-z]*[oO]\s*/(tmp|dev/shm|var/tmp)/", S.MEDIUM,
     "Descarga a una carpeta temporal"),
)
COMMAND_RULES = tuple((re.compile(p, re.I), sev, why) for p, sev, why in _COMMAND_RULES)

_MAX_TEXT = 64 * 1024  # no analizar más de 64 KB por texto


def evaluate_command(text: str) -> list[tuple[Severity, str]]:
    """Devuelve los (gravedad, motivo) que coinciden con el texto, de mayor a menor."""
    text = text[:_MAX_TEXT]
    hits = [(sev, why) for rx, sev, why in COMMAND_RULES if rx.search(text)]
    return sorted(hits, key=lambda hit: -hit[0])


# ---------------------------------------------------------------------------
# Ubicaciones sospechosas para un ejecutable
# ---------------------------------------------------------------------------
_UNIX_PREFIXES = (
    ("/dev/shm/", S.HIGH, "memoria compartida (/dev/shm)"),
    ("/run/shm/", S.HIGH, "memoria compartida (/run/shm)"),
    ("/var/tmp/", S.MEDIUM, "carpeta temporal /var/tmp"),
    ("/private/var/tmp/", S.MEDIUM, "carpeta temporal /private/var/tmp"),
    ("/private/tmp/", S.MEDIUM, "carpeta temporal /private/tmp"),
    ("/tmp/", S.MEDIUM, "carpeta temporal /tmp"),
)
_WINDOWS_FRAGMENTS = (
    ("/$recycle.bin/", S.HIGH, "papelera de reciclaje"),
    ("/appdata/local/temp/", S.MEDIUM, "carpeta temporal del usuario"),
    ("/windows/temp/", S.MEDIUM, "carpeta temporal de Windows"),
    ("/users/public/", S.MEDIUM, "carpeta pública de usuarios"),
)


def suspicious_location(path: str) -> Optional[tuple[Severity, str]]:
    """Si la ruta está en un lugar donde no suelen vivir programas legítimos."""
    norm = normalize_path(path)
    for prefix, sev, why in _UNIX_PREFIXES:
        if norm.startswith(prefix):
            return sev, why
    for fragment, sev, why in _WINDOWS_FRAGMENTS:
        if fragment in norm:
            return sev, why
    return None


# ---------------------------------------------------------------------------
# Suplantación de procesos del sistema
# ---------------------------------------------------------------------------
_SYS32 = ("/windows/system32/",)
_SYSTEM_BINARIES = {
    "svchost.exe": ("/windows/system32/", "/windows/syswow64/"),
    "lsass.exe": _SYS32, "csrss.exe": _SYS32, "smss.exe": _SYS32,
    "wininit.exe": _SYS32, "services.exe": _SYS32, "winlogon.exe": _SYS32,
    "taskhostw.exe": _SYS32, "conhost.exe": _SYS32,
    "explorer.exe": ("/windows/",),
}


def is_masquerading(name: str, exe: str) -> bool:
    """True si un nombre de proceso del sistema corre desde una carpeta incorrecta."""
    allowed = _SYSTEM_BINARIES.get(name.lower())
    if not allowed or not exe:
        return False
    norm = normalize_path(exe).split(":", 1)[-1]  # quita la letra de unidad
    return not any(norm.startswith(prefix) for prefix in allowed)


def is_fake_kernel_thread(cmdline: list[str], exe: str) -> bool:
    """Procesos que fingen ser hilos del kernel ('[kworker/0:1]') pero tienen binario."""
    return bool(exe and cmdline and cmdline[0].startswith("[") and cmdline[0].endswith("]"))


# Nombres de herramientas casi siempre maliciosas o no deseadas
KNOWN_BAD_NAMES = {
    "xmrig", "xmr-stak", "minerd", "cpuminer", "kdevtmpfsi", "kinsing",
    "mimikatz", "mimikatz.exe", "lazagne", "lazagne.exe",
}

# ---------------------------------------------------------------------------
# Red
# ---------------------------------------------------------------------------
BACKDOOR_PORTS = {
    4444: "puerto por defecto de Metasploit/shells inversas",
    1337: "puerto habitual en backdoors y herramientas de pentesting",
    31337: "Back Orifice",
    12345: "NetBus",
    27374: "SubSeven",
    6666: "botnets IRC",
    6667: "IRC (usado por botnets)",
    9050: "proxy SOCKS de Tor",
    9150: "Tor Browser (SOCKS)",
    2323: "telnet alternativo (Mirai)",
    3333: "pool de minería (stratum)",
    14444: "pool de minería (stratum)",
    5555: "ADB/RATs de Android",
}

SHELL_NAMES = {
    "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh",
    "cmd.exe", "powershell.exe", "pwsh.exe", "pwsh", "powershell",
    "nc", "ncat", "netcat", "nc.exe", "ncat.exe",
}

# Dominios de seguridad/actualización que el malware bloquea desde el archivo hosts
SECURITY_DOMAINS = (
    "windowsupdate.com", "update.microsoft.com", "defender.microsoft.com",
    "kaspersky.com", "avast.com", "avg.com", "avira.com", "bitdefender.com",
    "eset.com", "malwarebytes.com", "sophos.com", "mcafee.com", "symantec.com",
    "norton.com", "trendmicro.com", "clamav.net", "virustotal.com",
)


# ---------------------------------------------------------------------------
# Extracción del ejecutable de una línea de comandos
# ---------------------------------------------------------------------------
def extract_executable(command: str) -> Optional[str]:
    """Primer ejecutable de una línea de comandos (con o sin comillas), o None."""
    command = os.path.expandvars(command.strip())
    if not command:
        return None
    if command[0] in "\"'":
        end = command.find(command[0], 1)
        return command[1:end] if end > 0 else command[1:]
    first = command.split(None, 1)[0]
    # Rutas de Windows con espacios sin comillas: probar prefijos hasta que exista
    if " " in command and not os.path.exists(first) and ":" in first[:3]:
        words = command.split(" ")
        for i in range(2, len(words) + 1):
            candidate = " ".join(words[:i])
            if os.path.exists(candidate):
                return candidate
    return first

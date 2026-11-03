"""Menú interactivo con logo: es lo que ven protecx.bat / protecx.sh al abrirse sin argumentos.

Solo pregunta y construye los argumentos de `protecx scan|update|status`; el trabajo real
lo hace `cli.main`, así el menú y la línea de comandos se comportan igual.
"""

from __future__ import annotations

import getpass
import os
import sys
import webbrowser
from datetime import datetime, timezone
from importlib.util import find_spec
from pathlib import Path
from typing import Callable, Optional

import json

from . import __version__, clamav_setup, config, keystore, quarantine
from .signatures import SignatureStore
from .signatures.clamav import ClamAV
from .utils import host_info

_LOGO = (
    "██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗██╗  ██╗",
    "██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝╚██╗██╔╝",
    "██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║      ╚███╔╝ ",
    "██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║      ██╔██╗ ",
    "██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╗██╔╝ ██╗",
    "╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝",
)
_GRADIENT = (51, 45, 39, 33, 63, 99)   # cian → azul → violeta (colores ANSI de 256)
_WIDTH = 60

# (tecla, título, descripción)
_OPTIONS = (
    ("1", "Análisis completo", "todos los módulos sobre las zonas de riesgo"),
    ("2", "Análisis de red", "puertos, conexiones y «llamadas a casa» (60 s)"),
    ("3", "Análisis de archivos", "una carpeta a elegir o las zonas de riesgo"),
    ("4", "Procesos y arranque", "programas en marcha y qué se inicia solo"),
    ("5", "Disco entero", "revisa todo el disco (lento)"),
    ("6", "Actualizar firmas", "descarga virus y reglas nuevas"),
    ("7", "Estado de las firmas", "qué base de datos tienes y de cuándo"),
    ("8", "Abrir el último informe", "en el navegador"),
    ("9", "Cuarentena", "aislar archivos sospechosos (reversible)"),
    ("0", "Salir", ""),
)


def _options() -> tuple[tuple[str, str, str], ...]:
    """Las opciones fijas más «Instalar ClamAV» mientras ClamAV no esté instalado (antes de «Salir»)."""
    if ClamAV().available:
        return _OPTIONS
    return (*_OPTIONS[:-1], ("c", "Instalar ClamAV", "motor antivirus extra para los archivos"), _OPTIONS[-1])


class _Style:
    """Colores ANSI y marcos; cae a texto plano si la terminal no los admite."""

    def __init__(self, stream=None):
        stream = stream or sys.stdout
        if os.name == "nt":
            os.system("")  # activa los códigos ANSI en la consola de Windows 10+
        self.color = stream.isatty() and "NO_COLOR" not in os.environ
        try:
            "█╗┌─│✔✘".encode(getattr(stream, "encoding", None) or "ascii")
            self.fancy = True
        except (UnicodeEncodeError, LookupError):
            self.fancy = False

    def paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def fg(self, text: str, n: int, bold: bool = False) -> str:
        return self.paint(text, f"{'1;' if bold else ''}38;5;{n}")

    def dim(self, text: str) -> str:
        return self.paint(text, "90")


def _firmas(info: dict) -> tuple[str, bool]:
    """Resumen de las firmas y si conviene actualizarlas."""
    if not info["last_update"]:
        return "sin descargar: solo reglas integradas", True
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(info["last_update"])).days
    when = "hoy" if age == 0 else f"hace {age} día{'s' if age != 1 else ''}"
    return f"{info['hashes']:,} hashes · {info['iocs']:,} IOCs · {when}".replace(",", "."), age >= config.STALE_DB_DAYS


def render(style: _Style) -> str:
    host = host_info()
    firmas, stale = _firmas(SignatureStore().info())
    lines = [""]
    if style.fancy:
        lines += ["  " + style.fg(row, n, bold=True) for row, n in zip(_LOGO, _GRADIENT)]
    else:
        lines += ["  " + style.paint("P r o t e c X", "1;36")]
    lines += ["", "  " + style.dim(f"Escáner defensivo de malware · v{__version__} · solo lectura"), ""]

    ok, bad = style.paint("✔", "32") if style.fancy else "si", style.paint("✘", "31") if style.fancy else "no"
    rows = [
        ("Equipo", f"{host['os']} · " + (style.paint("administrador", "32") if host["admin"]
                                          else style.paint("sin privilegios (verás menos)", "33"))),
        ("Firmas", style.paint(firmas, "33") if stale else firmas),
        ("Motores", f"YARA {ok if find_spec('yara') else bad}   ClamAV {ok if ClamAV().available else bad}"),
    ]
    for label, value in rows:
        lines.append("   " + style.dim(f"{label:<8}") + value)
    lines.append("")

    for key, title, hint in _options():
        if key == "0":
            lines.append("")
        badge = style.paint("  ← recomendado", "33") if key == "6" and stale else ""
        lines.append("   " + style.fg(f"[{key.upper()}]", 45, bold=True) + f" {title:<24}" + style.dim(hint) + badge)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Acciones: cada una devuelve los argumentos para cli.main, o None si no hay nada que ejecutar
# ---------------------------------------------------------------------------
def _ask_folder(ask: Callable[[str], str]) -> Optional[list[str]]:
    answer = ask("  Carpeta a analizar (Enter = zonas de riesgo): ").strip().strip('"\'')
    if not answer:
        return []
    path = Path(answer).expanduser()
    if not path.is_dir():
        print(f"  «{answer}» no es una carpeta.")
        return None
    return ["--path", str(path)]


def _update_args(ask: Callable[[str], str]) -> list[str]:
    if os.environ.get(config.AUTH_KEY_ENV) or keystore.load():
        return ["update"]    # cli usa la del entorno o la guardada
    print("  abuse.ch exige una clave gratuita (https://auth.abuse.ch).")
    print("  Solo se pide esta vez: se guardará cifrada y se usará siempre.")
    key = getpass.getpass("  Pégala aquí (no se muestra; Enter = omitir esas fuentes): ").strip()
    if key and not keystore.is_valid(key):
        print("  Esa clave no tiene un formato válido (solo letras, números, «-» y «_»); se omite.")
        return ["update"]
    return ["update", "--auth-key", key] if key else ["update"]


def _open_last_report() -> None:
    reports = sorted(config.reports_dir().glob("protecx-*.html"))
    if not reports:
        print("  Todavía no hay informes: haz un análisis primero.")
        return
    print(f"  Abriendo {reports[-1]}")
    webbrowser.open(reports[-1].resolve().as_uri())


# ---------------------------------------------------------------------------
# Cuarentena
# ---------------------------------------------------------------------------
def _report_candidates() -> list[tuple[str, str, str]]:
    """(gravedad, ruta, título) de los archivos de gravedad media o superior del último informe JSON."""
    reports = sorted(config.reports_dir().glob("protecx-*.json"))
    if not reports:
        return []
    try:
        findings = json.loads(reports[-1].read_text(encoding="utf-8"))["findings"]
    except (OSError, ValueError, KeyError):
        return []
    seen, found = set(), []
    for f in findings:   # el informe ya viene ordenado de más a menos grave
        path = f.get("evidence", {}).get("ruta") or f.get("evidence", {}).get("ejecutable") or ""
        if f["severity"] in ("critical", "high", "medium") and path not in seen and os.path.isfile(path):
            seen.add(path)
            found.append((f["severity_label"], path, f["title"]))
    return found


def _numbers(answer: str, size: int) -> list[int]:
    if answer.strip().lower() in ("todos", "todo", "t"):
        return list(range(size))
    chosen = {int(n) - 1 for n in answer.replace(" ", "").split(",") if n.isdigit() and 0 < int(n) <= size}
    return sorted(chosen)


def _yes(ask: Callable[[str], str], question: str) -> bool:
    return ask(f"  {question} [s/N] ").strip().lower() in ("s", "si", "sí", "y", "yes")


def _quarantine_from_report(ask: Callable[[str], str]) -> None:
    candidates = _report_candidates()
    if not candidates:
        print("  No hay archivos sospechosos en el último informe (¿has hecho un análisis?).")
        return
    for number, (severity, path, title) in enumerate(candidates, start=1):
        print(f"  {number:>2}) [{severity}] {path}\n       {title}")
    picked = _numbers(ask("\n  Números separados por comas, o «todos» (Enter = cancelar): "), len(candidates))
    if not picked or not _yes(ask, f"Se aislarán {len(picked)} archivo(s). Se pueden restaurar. ¿Continuar?"):
        return
    for index in picked:
        _, path, title = candidates[index]
        try:
            item = quarantine.add(path, reason=title)
            print(f"  ✔ aislado: {path}  (id {item.id})")
        except quarantine.QuarantineError as exc:
            print(f"  ✘ {exc}")


def _print_quarantine(items: list[quarantine.Item]) -> None:
    for number, item in enumerate(items, start=1):
        print(f"  {number:>2}) {item.original}\n       {item.quarantined_at[:16].replace('T', ' ')} · {item.size:,} bytes"
              + (f" · {item.reason}" if item.reason else ""))


def _quarantine_menu(ask: Callable[[str], str]) -> None:
    while True:
        print("\n  [1] Aislar archivos del último informe   [2] Ver la cuarentena\n"
              "  [3] Restaurar un archivo                 [4] Eliminar para siempre      [0] Volver")
        choice = ask("  Cuarentena › ").strip()
        if choice == "0":
            return
        if choice == "1":
            _quarantine_from_report(ask)
        elif choice in ("2", "3", "4"):
            items = quarantine.list_items()
            if not items:
                print("  La cuarentena está vacía.")
                continue
            _print_quarantine(items)
            if choice == "2":
                continue
            picked = _numbers(ask("\n  Número (Enter = cancelar): "), len(items))[:1]
            if not picked:
                continue
            item = items[picked[0]]
            try:
                if choice == "3":
                    print(f"  ✔ restaurado en {quarantine.restore(item.id)}")
                elif _yes(ask, f"¿Eliminar {item.original} para siempre? No se puede deshacer."):
                    quarantine.delete(item.id)
                    print("  ✔ eliminado")
            except quarantine.QuarantineError as exc:
                print(f"  ✘ {exc}")


def _args_for(choice: str, ask: Callable[[str], str]) -> Optional[list[str]]:
    clam = ["--clamav"] if ClamAV().available else []   # motor extra solo si está instalado
    if choice == "1":
        return ["scan", "--open", *clam]
    if choice == "2":
        return ["scan", "--only", "network", "--monitor", "60", "--open"]
    if choice == "3":
        extra = _ask_folder(ask)
        return None if extra is None else ["scan", "--only", "files", "--open", *clam, *extra]
    if choice == "4":
        return ["scan", "--only", "processes", "persistence", "--open"]
    if choice == "5":
        sure = ask("  Revisará todo el disco y puede tardar mucho. ¿Continuar? [s/N] ").strip().lower()
        return ["scan", "--full", "--open", *clam] if sure in ("s", "si", "sí", "y", "yes") else None
    if choice == "6":
        return [*_update_args(ask), *clam]
    if choice == "7":
        return ["status"]
    if choice == "8":
        _open_last_report()
    if choice == "9":
        _quarantine_menu(ask)
    if choice == "c":
        clamav_setup.run(ask)
    return None


def run(ask: Callable[[str], str] = input) -> int:
    from .cli import main as cli_main  # import tardío: cli importa este módulo

    style = _Style()
    while True:
        valid = {key for key, _, _ in _options()}
        os.system("cls" if os.name == "nt" else "clear")
        print(render(style))
        try:
            choice = ask("\n  " + style.fg("Elige una opción", 45, bold=True) + " › ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice == "0":
            print("  Hasta pronto.")
            return 0
        if choice not in valid:
            continue
        print()
        try:
            args = _args_for(choice, ask)
            if args:
                cli_main(args)
            ask("\n  Pulsa Enter para volver al menú… ")
        except (EOFError, KeyboardInterrupt):
            print()

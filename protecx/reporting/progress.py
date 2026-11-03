"""Barra de progreso de una sola línea para la terminal (stderr).

Protocolo de `progress(message, *, stage=None, stages=None, count=None)`:
  - con `stage`/`stages`: empieza un módulo (`message` es su nombre);
  - con `count`: actualiza el contador del módulo en curso (`message` es la unidad);
  - sin nada: mensaje suelto, que se imprime sin romper la barra.
Como no se conoce de antemano cuántos archivos hay, la barra avanza por módulos y
el tramo en curso muestra un marcador que se desplaza. Fuera de una terminal
(redirección a fichero) se escriben líneas normales.
"""

from __future__ import annotations

import shutil
import sys
import time
from typing import TextIO

_WIDTH = 24
_MARKER = 3


class ScanProgress:
    def __init__(self, stream: TextIO = sys.stderr):
        self._out = stream
        self._tty = stream.isatty()
        self._full, self._empty, self._mark = self._glyphs(stream)
        self._started = time.monotonic()
        self._stage = self._stages = self._tick = 0
        self._label = ""
        self._count_text = ""
        self._drawn = False

    @staticmethod
    def _glyphs(stream: TextIO) -> tuple[str, str, str]:
        try:  # consolas antiguas no admiten bloques Unicode
            "█░▓".encode(getattr(stream, "encoding", None) or "ascii")
            return "█", "░", "▓"
        except (UnicodeEncodeError, LookupError):
            return "#", "-", "="

    def __call__(self, message: str, *, stage: int | None = None, stages: int | None = None,
                 count: int | None = None) -> None:
        if stage is not None:
            self._stage, self._stages, self._label, self._count_text = stage, stages or 0, message, ""
            line = f"Analizando: {message}…"
        elif count is not None:
            self._count_text = f"{count:,} {message}".replace(",", ".")
            line = f"{message.capitalize()} analizados: {count}"
        else:
            line = message
        self._tick += 1
        if self._tty:
            if stage is None and count is None:
                self._clear()
                print(line, file=self._out, flush=True)
            self._draw()
        elif stage is not None or count is None or count % 5000 < 500:  # sin terminal: pocas líneas
            print(line, file=self._out, flush=True)

    def _bar(self) -> str:
        if not self._stages:
            return self._empty * _WIDTH
        done = round(_WIDTH * (self._stage - 1) / self._stages)
        segment = max(_MARKER, _WIDTH // self._stages)
        offset = self._tick % (segment - _MARKER + 1)
        bar = self._full * done + self._empty * offset + self._mark * _MARKER
        return (bar + self._empty * _WIDTH)[:_WIDTH]

    def _draw(self) -> None:
        elapsed = int(time.monotonic() - self._started)
        parts = [f"[{self._bar()}] {self._stage}/{self._stages} {self._label}", self._count_text,
                 f"{elapsed // 60}:{elapsed % 60:02d}"]
        line = " · ".join(p for p in parts if p)
        width = shutil.get_terminal_size().columns - 1
        self._out.write("\r" + line[:width].ljust(width))
        self._out.flush()
        self._drawn = True

    def _clear(self) -> None:
        if self._drawn:
            self._out.write("\r" + " " * (shutil.get_terminal_size().columns - 1) + "\r")
            self._drawn = False

    def close(self) -> None:
        """Borra la barra para que el resumen final salga limpio."""
        if self._tty:
            self._clear()
            self._out.flush()
